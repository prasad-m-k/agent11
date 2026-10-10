package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// testPolicyJSON is a small valid policy shared by the tests.
const testPolicyJSON = `{
  "version": 1,
  "mode": "report",
  "destinations": {
    "approved": ["api.company-llm.example"],
    "public": ["api.anthropic.com", "api.openai.com"]
  },
  "classes": [
    {
      "id": "code", "description": "Proprietary source code", "owner": "engineering",
      "detectors": {"source_labels": ["repo:core"], "path_globs": ["**/core-platform/**"], "keywords": ["ProjectX"]},
      "classifier": {"enabled": true, "block_at": 0.9, "hold_at": 0.5},
      "actions": {"approved": "allow", "public": "block"}
    },
    {
      "id": "creds", "description": "Access credentials", "owner": "security",
      "detectors": {"rules": ["aws-access-key", "re:\\bINTERNAL-[0-9]{4}\\b"]},
      "actions": {"approved": "block", "public": "block"},
      "mode": "enforce"
    },
    {
      "id": "customers", "description": "Customer records", "owner": "privacy",
      "detectors": {"fingerprints": ["FINGERPRINT"]},
      "classifier": {"enabled": true, "block_at": 0.95},
      "actions": {"approved": "allow", "public": "hold"}
    }
  ]
}`

func mustPolicy(t *testing.T, js string) *Policy {
	t.Helper()
	p, err := parsePolicy([]byte(strings.ReplaceAll(js, "FINGERPRINT", sha256Hex(knownDocLine))))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const knownDocLine = "Quarterly customer retention list, rows follow"

func TestPolicyValid(t *testing.T) {
	p := mustPolicy(t, testPolicyJSON)
	if len(p.Classes) != 3 {
		t.Fatalf("classes = %d", len(p.Classes))
	}
	if cat, ok := p.category("API.Anthropic.com:443"); !ok || cat != "public" {
		t.Errorf("category = %q, %v", cat, ok)
	}
	if _, ok := p.category("evil-anthropic.com"); ok {
		t.Error("suffix without a dot boundary must not match")
	}
	if v := p.Classes[0].action("unlisted"); v != VerdictBlock {
		t.Errorf("unlisted destination action = %v, want strictest (block)", v)
	}
}

func TestPolicyValidation(t *testing.T) {
	base := testPolicyJSON
	tests := []struct {
		name, from, to, want string
	}{
		{"version", `"version": 1`, `"version": 2`, `"version"`},
		{"global mode", `"mode": "report"`, `"mode": "audit"`, `"mode"`},
		{"missing description", `"description": "Proprietary source code", `, ``, `class "code": field "description"`},
		{"missing owner", `"owner": "security",`, ``, `class "creds": field "owner"`},
		{"missing action", `"actions": {"approved": "allow", "public": "block"}`, `"actions": {"approved": "allow"}`, `class "code": field "actions": missing destination category "public"`},
		{"unknown category", `"actions": {"approved": "block", "public": "block"}`, `"actions": {"approved": "block", "public": "block", "chat": "block"}`, `unknown destination category "chat"`},
		{"bad verdict", `"public": "block"}`, `"public": "deny"}`, `"deny"`},
		{"unknown rule", `"aws-access-key"`, `"aws-key"`, `class "creds": field "rules"`},
		{"bad regexp", `re:\\bINTERNAL`, `re:(`, `field "rules"`},
		{"bad threshold", `"block_at": 0.9, "hold_at": 0.5`, `"block_at": 0.5, "hold_at": 0.9`, `classifier.hold_at`},
		{"bad fingerprint", `["FINGERPRINT"]`, `["abc"]`, `field "fingerprints"`},
		{"unknown field", `"keywords": ["ProjectX"]`, `"keyword": ["ProjectX"]`, `unknown field "keyword"`},
		{"class mode", `"mode": "enforce"`, `"mode": "on"`, `class "creds": field "mode"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			js := strings.Replace(base, tt.from, tt.to, 1)
			if js == base {
				t.Fatalf("replacement %q not found", tt.from)
			}
			js = strings.ReplaceAll(js, "FINGERPRINT", sha256Hex(knownDocLine))
			_, err := parsePolicy([]byte(js))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %s", err, tt.want)
			}
		})
	}
}

func TestGlobRegexp(t *testing.T) {
	tests := []struct {
		glob, path string
		want       bool
	}{
		{"**/core-platform/**", "/home/dev/core-platform/a/b.go", true},
		{"**/core-platform/**", "core-platform/x", true},
		{"**/core-platform/**", "/home/dev/core-platform-old/x", false},
		{"src/*.go", "src/main.go", true},
		{"src/*.go", "src/pkg/main.go", false},
		{"src/?.go", "src/a.go", true},
	}
	for _, tt := range tests {
		re, err := globRegexp(tt.glob)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.MatchString(tt.path); got != tt.want {
			t.Errorf("%s ~ %s = %v, want %v", tt.glob, tt.path, got, tt.want)
		}
	}
}
