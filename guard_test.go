package main

import (
	"log/slog"
	"strings"
	"testing"
)

func TestClipboardGuardTrigger(t *testing.T) {
	cardText := "4111 1111 1111 1111 12/28 123"
	tests := []struct {
		name, mode, rules string
		text              string
		keywords          []string
		aiContext         bool
		want              string
	}{
		{"off never acts", guardOff, defaultGuardRules, cardText, nil, true, ""},
		{"ai mode acts with an AI site open", guardAI, defaultGuardRules, cardText, nil, true, "credit-card:1"},
		{"ai mode waits without AI context", guardAI, defaultGuardRules, cardText, nil, false, ""},
		{"always acts without AI context", guardAlways, defaultGuardRules, cardText, nil, false, "credit-card:1"},
		{"email alone is not guarded", guardAlways, defaultGuardRules, "mail ops@example.com", nil, true, ""},
		{"only guarded rules are named", guardAlways, defaultGuardRules, "ops@example.com " + cardText, nil, true, "credit-card:1"},
		{"keyword wildcard", guardAlways, defaultGuardRules, "ProjectX roadmap", []string{"ProjectX"}, true, "keyword:ProjectX:1"},
		{"custom rule list", guardAlways, "us-ssn", cardText, nil, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := newClipboardGuard(tt.mode, tt.rules)
			if err != nil {
				t.Fatal(err)
			}
			hit := g.trigger(newDLPScanner(tt.keywords).scan(tt.text), tt.aiContext)
			if got := summary(hit); got != tt.want {
				t.Errorf("trigger = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClipboardGuardFlags(t *testing.T) {
	if _, err := newClipboardGuard("on", defaultGuardRules); err == nil {
		t.Error("want an error for an unknown mode")
	}
	if _, err := newClipboardGuard(guardAI, "credit-card,cc"); err == nil || !strings.Contains(err.Error(), `"cc"`) {
		t.Errorf("err = %v, want it to name the unknown rule", err)
	}
}

func TestGuardNoticeHoldsNoContent(t *testing.T) {
	text := "4111 1111 1111 1111"
	n := guardNotice(newDLPScanner(nil).scan(text))
	if strings.Contains(n, "4111") || !strings.Contains(n, "credit-card:1") {
		t.Errorf("notice = %q", n)
	}
	// The notice must not trip the guard itself, or it would loop.
	g, _ := newClipboardGuard(guardAlways, defaultGuardRules)
	if hit := g.trigger(newDLPScanner(nil).scan(n), true); len(hit) > 0 {
		t.Errorf("notice triggers the guard: %v", hit)
	}
}

func TestAIContext(t *testing.T) {
	ai := newAIWatcher(slog.Default())
	if ai.anyDesktop() {
		t.Fatal("empty watcher reports a desktop app")
	}
	ai.running["Claude Code"] = true
	if ai.anyDesktop() {
		t.Error("a CLI agent is not a window anyone pastes into")
	}
	ai.running["ChatGPT"] = true
	if !ai.anyDesktop() {
		t.Error("ChatGPT desktop should count")
	}
	for _, name := range desktopAIApps {
		found := false
		for _, a := range aiApps {
			found = found || a.name == name
		}
		if !found {
			t.Errorf("desktopAIApps entry %q is not an aiApps name", name)
		}
	}
	b := newBrowserWatcher(slog.Default())
	b.open["gemini.google.com"] = true
	if !b.anyOpen() {
		t.Error("open AI site should count")
	}
}
