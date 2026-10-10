package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mycoderAdapter = `{
  "name": "mycoder", "config_style": "args",
  "fields": { "session": "sessionId", "turn": "turnId", "request": "callId", "model": "model", "tool": "toolName" },
  "tool_classes": { "AskHuman": "ask_user_question", "ReviewPlan": "exit_plan_mode" },
  "events": {
    "start":    { "kind": "agent_session_started" },
    "prompt":   { "kind": "agent_turn_started" },
    "tool":     { "kind": "agent_tool_activity", "use_request": true,
                  "by_tool_class": { "ask_user_question": "agent_question_requested", "exit_plan_mode": "agent_plan_review_requested" } },
    "tool_end": { "kind": "agent_attention_resolved", "use_request": true, "require_request_for_classes": ["ask_user_question","exit_plan_mode"] },
    "stop":     { "kind": "agent_turn_completed", "by_field": { "field": "error", "present": "agent_error" } }
  }
}`

func mustAdapter(t *testing.T, js string) *HookAdapter {
	t.Helper()
	var a HookAdapter
	if err := json.Unmarshal([]byte(js), &a); err != nil {
		t.Fatal(err)
	}
	if err := a.compile(); err != nil {
		t.Fatal(err)
	}
	return &a
}

func TestAdapterMapping(t *testing.T) {
	a := mustAdapter(t, mycoderAdapter)
	now := metricsBase.UnixMilli()
	tests := []struct {
		event, payload, kind, session, toolClass string
		ok                                       bool
	}{
		{"start", `{"sessionId":"s1","model":"gpt-9","prompt":"SECRET"}`, kindSessionStarted, "s1", "", true},
		{"prompt", `{"sessionId":"s1","turnId":"t1"}`, kindTurnStarted, "s1", "", true},
		{"tool", `{"sessionId":"s1","toolName":"Bash","callId":"c1"}`, kindToolActivity, "s1", "other", true},
		{"tool", `{"sessionId":"s1","toolName":"AskHuman","callId":"c2"}`, kindQuestionRequested, "s1", "ask_user_question", true},
		{"tool", `{"sessionId":"s1","toolName":"ReviewPlan","callId":"c3"}`, kindPlanReviewRequest, "s1", "exit_plan_mode", true},
		{"tool_end", `{"sessionId":"s1","toolName":"AskHuman","callId":"c2"}`, kindAttentionResolved, "s1", "ask_user_question", true},
		{"tool_end", `{"sessionId":"s1","toolName":"AskHuman"}`, "", "s1", "ask_user_question", false}, // missing request
		{"stop", `{"sessionId":"s1"}`, kindTurnCompleted, "s1", "", true},
		{"stop", `{"sessionId":"s1","error":"boom"}`, kindAgentError, "s1", "", true},
		{"nope", `{"sessionId":"s1"}`, "", "", "", false},
		{"STOP", `{"sessionId":"s1"}`, kindTurnCompleted, "s1", "", true}, // case-insensitive match
	}
	for _, tt := range tests {
		var obj map[string]any
		if err := json.Unmarshal([]byte(tt.payload), &obj); err != nil {
			t.Fatal(err)
		}
		e, ok := mapWithAdapter(a, tt.event, obj, now)
		if ok != tt.ok || (ok && (e.Kind != tt.kind || e.SessionID != tt.session || e.ToolClass != tt.toolClass)) {
			t.Errorf("%s %s -> kind=%q session=%q class=%q ok=%v, want %q/%q/%q/%v",
				tt.event, tt.payload, e.Kind, e.SessionID, e.ToolClass, ok, tt.kind, tt.session, tt.toolClass, tt.ok)
		}
		if ok && e.AgentKind != "mycoder" {
			t.Errorf("%s: agent kind %q", tt.event, e.AgentKind)
		}
		if out, _ := json.Marshal(e); strings.Contains(string(out), "SECRET") {
			t.Errorf("%s: event carries content: %s", tt.event, out)
		}
	}
}

func TestAdapterValidation(t *testing.T) {
	cases := map[string]string{
		"missing name":     `{"config_style":"args","fields":{"session":"s"},"events":{"x":{"kind":"agent_turn_started"}}}`,
		"reserved name":    `{"name":"claude-code","fields":{"session":"s"},"events":{"x":{"kind":"agent_turn_started"}}}`,
		"bad name":         `{"name":"my coder","fields":{"session":"s"},"events":{"x":{"kind":"agent_turn_started"}}}`,
		"no session field": `{"name":"m","fields":{},"events":{"x":{"kind":"agent_turn_started"}}}`,
		"bad style":        `{"name":"m","config_style":"weird","fields":{"session":"s"},"events":{"x":{"kind":"agent_turn_started"}}}`,
		"unknown kind":     `{"name":"m","fields":{"session":"s"},"events":{"x":{"kind":"agent_flossing"}}}`,
		"bad tool class":   `{"name":"m","fields":{"session":"s"},"tool_classes":{"T":"nope"},"events":{"x":{"kind":"agent_turn_started"}}}`,
		"no events":        `{"name":"m","fields":{"session":"s"},"events":{}}`,
	}
	for name, js := range cases {
		var a HookAdapter
		if err := json.Unmarshal([]byte(js), &a); err != nil {
			t.Fatalf("%s: json: %v", name, err)
		}
		if err := a.compile(); err == nil {
			t.Errorf("%s: compile accepted an invalid adapter", name)
		}
	}
}

func TestLoadAdapterDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "mycoder.json"), []byte(mycoderAdapter), 0o600)
	os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{"name":"b","events":{}}`), 0o600)
	os.WriteFile(filepath.Join(dir, "notjson.txt"), []byte("ignored"), 0o600)

	loaded, errs := loadAdapterDir(dir)
	if loaded["mycoder"] == nil {
		t.Error("mycoder not loaded")
	}
	if len(errs) != 1 {
		t.Errorf("errs = %v, want 1 (broken.json)", errs)
	}
	// A missing directory is fine.
	if _, errs := loadAdapterDir(filepath.Join(dir, "nope")); len(errs) != 0 {
		t.Errorf("missing dir errs = %v", errs)
	}
	// Unknown fields are rejected, so a typo cannot silently disable a rule.
	os.WriteFile(filepath.Join(dir, "typo.json"), []byte(`{"name":"t","fields":{"session":"s"},"evnts":{}}`), 0o600)
	_, errs = loadAdapterDir(dir)
	if len(errs) != 2 {
		t.Errorf("errs with typo = %d, want 2", len(errs))
	}
}

func TestRenderCustomConfig(t *testing.T) {
	a := mustAdapter(t, mycoderAdapter)
	out := renderHookConfig(a, "/opt/agent11")
	var cfg struct {
		Hooks map[string][]struct {
			Hooks []struct{ Command string }
		}
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hooks) != 5 || !strings.Contains(cfg.Hooks["prompt"][0].Hooks[0].Command, "hook --agent mycoder prompt") {
		t.Errorf("config = %s", out)
	}

	// Antigravity style nests under agent11 and keeps matchers.
	ag := mustAdapter(t, `{"name":"myide","config_style":"antigravity","fields":{"session":"c"},
		"events":{"PreTool":{"kind":"agent_tool_activity","matcher":"*"},"Done":{"kind":"agent_turn_completed"}}}`)
	var acfg struct {
		A map[string][]struct {
			Matcher string
			Hooks   []struct{ Command string }
		} `json:"agent11"`
	}
	if err := json.Unmarshal([]byte(renderHookConfig(ag, "x")), &acfg); err != nil {
		t.Fatal(err)
	}
	if acfg.A["PreTool"][0].Matcher != "*" || acfg.A["Done"][0].Matcher != "" {
		t.Errorf("antigravity matcher wrong: %+v", acfg.A)
	}
}

func TestMapAgentPayloadUsesCustomRegistry(t *testing.T) {
	customAdapters = map[string]*HookAdapter{} // isolate from other tests
	customAdapters["mycoder"] = mustAdapter(t, mycoderAdapter)
	t.Cleanup(func() { customAdapters = map[string]*HookAdapter{} })

	e, ok := mapAgentPayload("mycoder", "prompt", map[string]any{"sessionId": "s1"}, metricsBase)
	if !ok || e.Kind != kindTurnStarted || e.AgentKind != "mycoder" {
		t.Errorf("custom dispatch: %+v ok=%v", e, ok)
	}
	if _, ok := mapAgentPayload("ghost", "x", map[string]any{}, metricsBase); ok {
		t.Error("unknown agent mapped")
	}
	if out, err := hooksSnippet("mycoder", "bin"); err != nil || !strings.Contains(out, "hook --agent mycoder") {
		t.Errorf("snippet for custom agent: %v", err)
	}
}
