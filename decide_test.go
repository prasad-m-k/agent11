package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeClassifier returns fixed probabilities, or an error, and records what
// it was shown.
type fakeClassifier struct {
	probs map[string]float64
	err   error
	delay time.Duration
	calls int
	seen  ClassifierInput
	asked []string
}

func (f *fakeClassifier) Name() string { return "fake" }
func (f *fakeClassifier) Classify(ctx context.Context, in ClassifierInput, cs []*Class) (map[string]float64, error) {
	f.calls++
	f.seen = in
	for _, c := range cs {
		f.asked = append(f.asked, c.ID)
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.probs, f.err
}

// testAWSKey builds an access-key-shaped string from the pattern, never a real key.
var testAWSKey = "AKIA" + strings.Repeat("Q", 16)

func TestDecide(t *testing.T) {
	tests := []struct {
		name        string
		req         decideRequest
		clf         *fakeClassifier
		modeFlag    string
		wantVerdict Verdict
		wantApplied Verdict
		wantClasses []string
		wantRule    string
		wantClf     string
	}{
		{
			name:        "clean text is allowed without the classifier when nothing could change",
			req:         decideRequest{Text: "how do I sort a slice", Destination: "api.company-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictAllow, wantClf: "not-needed",
		},
		{
			name:        "source label",
			req:         decideRequest{Text: "hello", Labels: []string{"repo:core"}, Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictBlock, wantClasses: []string{"code"}, wantRule: "label:repo:core",
		},
		{
			name:        "path glob",
			req:         decideRequest{Text: "see /src/core-platform/billing/x.go line 3", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictBlock, wantClasses: []string{"code"}, wantRule: "path-glob",
		},
		{
			name:        "keyword is case-insensitive",
			req:         decideRequest{Text: "the projectx launch", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictBlock, wantClasses: []string{"code"}, wantRule: "keyword",
		},
		{
			name:        "built-in rule in an enforce class is applied",
			req:         decideRequest{Text: "key " + testAWSKey, Destination: "api.company-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictBlock, wantApplied: VerdictBlock, wantClasses: []string{"creds"}, wantRule: "rule:aws-access-key",
		},
		{
			name:        "policy regexp rule",
			req:         decideRequest{Text: "ticket INTERNAL-1234", Destination: "api.openai.com"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictBlock, wantApplied: VerdictBlock, wantClasses: []string{"creds"}, wantRule: "rule:re:\\bINTERNAL-[0-9]{4}\\b",
		},
		{
			name:        "fingerprint of a quoted line",
			req:         decideRequest{Text: "intro\n  " + knownDocLine + "  \nmore", Destination: "api.openai.com"},
			clf:         &fakeClassifier{probs: map[string]float64{}},
			wantVerdict: VerdictHold, wantClasses: []string{"customers"}, wantRule: "fingerprint",
		},
		{
			name:        "approved destination allows a matched class",
			req:         decideRequest{Text: "ProjectX", Destination: "api.company-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictAllow, wantClasses: []string{"code"}, wantRule: "keyword",
		},
		{
			name:        "unlisted destination gets the strictest action",
			req:         decideRequest{Text: "ProjectX", Destination: "unknown-llm.example"},
			clf:         &fakeClassifier{},
			wantVerdict: VerdictBlock, wantClasses: []string{"code"}, wantRule: "keyword",
		},
		{
			name:        "classifier over block_at",
			req:         decideRequest{Text: "some ambiguous code", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{probs: map[string]float64{"code": 0.95}},
			wantVerdict: VerdictBlock, wantClasses: []string{"code"}, wantRule: "classifier", wantClf: "used",
		},
		{
			name:        "classifier in the hold band",
			req:         decideRequest{Text: "some ambiguous code", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{probs: map[string]float64{"code": 0.6}},
			wantVerdict: VerdictHold, wantClasses: []string{"code"}, wantRule: "classifier", wantClf: "used",
		},
		{
			name:        "classifier below hold_at",
			req:         decideRequest{Text: "some ambiguous code", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{probs: map[string]float64{"code": 0.2}},
			wantVerdict: VerdictAllow, wantClf: "used",
		},
		{
			name:        "classifier error without labels falls back to allow",
			req:         decideRequest{Text: "text", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{err: errors.New("down")},
			wantVerdict: VerdictAllow, wantClf: "unavailable",
		},
		{
			name:        "classifier error with an unmatched label blocks",
			req:         decideRequest{Text: "text", Labels: []string{"share:finance"}, Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{err: errors.New("down")},
			modeFlag:    modeEnforce,
			wantVerdict: VerdictBlock, wantApplied: VerdictBlock, wantClasses: []string{"labeled-unclassified"},
			wantRule: "classifier-unavailable", wantClf: "unavailable",
		},
		{
			name:        "mode flag enforces classes without their own mode",
			req:         decideRequest{Text: "ProjectX", Destination: "api.anthropic.com"},
			clf:         &fakeClassifier{},
			modeFlag:    modeEnforce,
			wantVerdict: VerdictBlock, wantApplied: VerdictBlock, wantClasses: []string{"code"}, wantRule: "keyword",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDecider(mustPolicy(t, testPolicyJSON), tt.clf, time.Second, tt.modeFlag)
			got := d.decide(context.Background(), tt.req)
			if got.Verdict != tt.wantVerdict || got.Applied != tt.wantApplied {
				t.Errorf("verdict/applied = %v/%v, want %v/%v", got.Verdict, got.Applied, tt.wantVerdict, tt.wantApplied)
			}
			if !slices.Equal(got.Classes, tt.wantClasses) {
				t.Errorf("classes = %v, want %v", got.Classes, tt.wantClasses)
			}
			if tt.wantRule != "" && !slices.Contains(got.Rules, tt.wantRule) {
				t.Errorf("rules = %v, want %s", got.Rules, tt.wantRule)
			}
			if tt.wantClf != "" && got.Classifier != tt.wantClf {
				t.Errorf("classifier = %s, want %s", got.Classifier, tt.wantClf)
			}
		})
	}
}

func TestDecideSkipsClassifierWhenBlocked(t *testing.T) {
	clf := &fakeClassifier{probs: map[string]float64{"customers": 1}}
	d := newDecider(mustPolicy(t, testPolicyJSON), clf, time.Second, "")
	got := d.decide(context.Background(), decideRequest{Text: "ProjectX", Destination: "api.anthropic.com"})
	if clf.calls != 0 {
		t.Errorf("classifier called %d times after a deterministic block", clf.calls)
	}
	if got.Verdict != VerdictBlock {
		t.Errorf("verdict = %v", got.Verdict)
	}
}

func TestDecideClassifierTimeoutFallsBack(t *testing.T) {
	clf := &fakeClassifier{probs: map[string]float64{"code": 1}, delay: time.Second}
	d := newDecider(mustPolicy(t, testPolicyJSON), clf, 20*time.Millisecond, "")
	start := time.Now()
	got := d.decide(context.Background(), decideRequest{Text: "x", Destination: "api.anthropic.com"})
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Errorf("decide took %s; the classifier timeout did not bound it", el)
	}
	if got.Classifier != "unavailable" || got.Verdict != VerdictAllow {
		t.Errorf("classifier/verdict = %s/%v, want unavailable/allow", got.Classifier, got.Verdict)
	}
}

func TestDecideClassifierSeesFeaturesNotContent(t *testing.T) {
	secret := "the merger closes Friday at 41 dollars a share"
	clf := &fakeClassifier{probs: map[string]float64{}}
	d := newDecider(mustPolicy(t, testPolicyJSON), clf, time.Second, "")
	d.decide(context.Background(), decideRequest{Text: secret + "\nsee /a/core/b.txt CONFIDENTIAL", Destination: "api.anthropic.com"})
	if clf.calls != 1 {
		t.Fatalf("calls = %d", clf.calls)
	}
	if clf.seen.Raw != "" || strings.Contains(clf.seen.Features, "merger") {
		t.Errorf("classifier saw content: %+v", clf.seen)
	}
	for _, want := range []string{"document_markers: confidential", "path_directories: a, core", "length_chars:"} {
		if !strings.Contains(clf.seen.Features, want) {
			t.Errorf("features missing %q:\n%s", want, clf.seen.Features)
		}
	}
}

func TestDecideRawOptIn(t *testing.T) {
	js := strings.Replace(testPolicyJSON, `"block_at": 0.9, "hold_at": 0.5`, `"block_at": 0.9, "hold_at": 0.5, "classifier_raw": true`, 1)
	clf := &fakeClassifier{probs: map[string]float64{}}
	d := newDecider(mustPolicy(t, js), clf, time.Second, "")
	d.decide(context.Background(), decideRequest{Text: "raw text", Destination: "api.anthropic.com"})
	if clf.seen.Raw != "raw text\n" && clf.seen.Raw != "raw text" {
		t.Errorf("raw = %q, want the text for an opted-in class", clf.seen.Raw)
	}
	if got := mustPolicy(t, js).rawClassifierClasses(); !slices.Equal(got, []string{"code"}) {
		t.Errorf("rawClassifierClasses = %v", got)
	}
}

func TestDecisionCarriesNoContent(t *testing.T) {
	text := "ProjectX " + testAWSKey + " " + knownDocLine
	d := newDecider(mustPolicy(t, testPolicyJSON), &fakeClassifier{}, time.Second, "")
	got := d.decide(context.Background(), decideRequest{Text: text, Destination: "api.anthropic.com", AgentID: "a1"})
	all := strings.Join(append(append([]string{}, got.Rules...), got.Classes...), " ")
	for _, frag := range []string{testAWSKey, knownDocLine} {
		if strings.Contains(all, frag) {
			t.Errorf("decision leaks %q: %+v", frag, got)
		}
	}
	if got.AgentIDSource != "declared" {
		t.Errorf("agent_id_source = %q, want declared", got.AgentIDSource)
	}
}
