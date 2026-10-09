package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// dlpRule flags a class of sensitive data by pattern. validate, when set, does
// a second check on each match (e.g. Luhn) to cut false positives.
type dlpRule struct {
	name     string
	re       *regexp.Regexp
	validate func(string) bool
}

// builtinRules detect common secrets and PII. They match structure, not the
// secret's value, so nothing here needs a real credential to test.
var builtinRules = []dlpRule{
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{name: "aws-access-key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "gcp-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{name: "openai-key", re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)},
	{name: "anthropic-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\bgh[opsu]_[A-Za-z0-9]{36,}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{name: "email", re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{name: "us-ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{name: "credit-card", re: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), validate: luhnValid},
}

// luhnValid reports whether the digits in s pass the Luhn checksum, which
// every real card number does. It filters out arbitrary long digit strings.
func luhnValid(s string) bool {
	var sum, n int
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
		n++
	}
	return n >= 13 && sum%10 == 0
}

type finding struct {
	rule  string
	count int
}

// dlpScanner holds the active rule set: built-ins plus any user keywords.
type dlpScanner struct {
	rules []dlpRule
}

// newDLPScanner builds a scanner. Each keyword becomes a case-insensitive
// literal rule named "keyword:<word>", for internal markers like a project
// codename or "CONFIDENTIAL".
func newDLPScanner(keywords []string) *dlpScanner {
	rules := append([]dlpRule(nil), builtinRules...)
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		rules = append(rules, dlpRule{
			name: "keyword:" + kw,
			re:   regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw)),
		})
	}
	return &dlpScanner{rules: rules}
}

// scan returns one finding per rule that matched, with a count. It never
// returns the matched text, so callers can log findings without re-recording
// the sensitive value.
func (s *dlpScanner) scan(text string) []finding {
	var out []finding
	for _, r := range s.rules {
		matches := r.re.FindAllString(text, -1)
		n := 0
		for _, m := range matches {
			if r.validate == nil || r.validate(m) {
				n++
			}
		}
		if n > 0 {
			out = append(out, finding{rule: r.name, count: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rule < out[j].rule })
	return out
}

// summary renders findings as "rule:count,rule:count" for a log field.
func summary(fs []finding) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = fmt.Sprintf("%s:%d", f.rule, f.count)
	}
	return strings.Join(parts, ",")
}
