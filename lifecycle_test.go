package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMapHookPayload(t *testing.T) {
	now := metricsBase
	tests := []struct {
		event   string
		payload string
		kind    string
		ok      bool
	}{
		{"SessionStart", `{"session_id":"s1","model":"claude-opus-5-5","source":"startup"}`, kindSessionStarted, true},
		{"SessionEnd", `{"session_id":"s1","prompt_id":"p9"}`, kindSessionEnded, true},
		{"UserPromptSubmit", `{"session_id":"s1","prompt_id":"p1","prompt":"refactor the billing module for ProjectX"}`, kindTurnStarted, true},
		{"Stop", `{"session_id":"s1"}`, kindTurnCompleted, true},
		{"StopFailure", `{"session_id":"s1"}`, kindAgentError, true},
		{"PreToolUse", `{"session_id":"s1","tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"cat secrets.env"}}`, kindToolActivity, true},
		{"PreToolUse", `{"session_id":"s1","tool_name":"AskUserQuestion","tool_use_id":"q1"}`, kindQuestionRequested, true},
		{"PreToolUse", `{"session_id":"s1","tool_name":"ExitPlanMode","tool_use_id":"x1"}`, kindPlanReviewRequest, true},
		{"PostToolUse", `{"session_id":"s1","tool_name":"AskUserQuestion","tool_use_id":"q1","tool_response":"the answer"}`, kindAttentionResolved, true},
		{"PostToolUse", `{"session_id":"s1","tool_name":"AskUserQuestion"}`, "", false},
		{"PostToolUse", `{"session_id":"s1","tool_name":"Edit","tool_use_id":"t2","tool_response":{"diff":"..."}}`, kindToolActivity, true},
		{"PermissionRequest", `{"session_id":"s1","tool_name":"Bash","tool_use_id":"t3"}`, kindApprovalRequested, true},
		{"PermissionRequest", `{"session_id":"s1","tool_name":"AskUserQuestion","tool_use_id":"q2"}`, "", false},
		{"Notification", `{"session_id":"s1","notification_type":"permission_prompt","message":"Claude needs permission to run rm"}`, kindApprovalRequested, true},
		{"Notification", `{"session_id":"s1","notification_type":"idle_prompt","message":"waiting"}`, kindAgentObservation, true},
		{"SubagentStart", `{"session_id":"s1","agent_id":"a1"}`, kindChildSpawned, true},
		{"SubagentStop", `{"session_id":"s1","agent_id":"a1"}`, kindChildCompleted, true},
		{"", `{"hook_event_name":"Stop","session_id":"s1"}`, kindTurnCompleted, true}, // name from the payload
		{"PreCompact", `{"session_id":"s1"}`, "", false},
	}
	for _, tt := range tests {
		var obj map[string]any
		if err := json.Unmarshal([]byte(tt.payload), &obj); err != nil {
			t.Fatal(err)
		}
		e, ok := mapHookPayload(tt.event, obj, now)
		if ok != tt.ok || (ok && e.Kind != tt.kind) {
			t.Errorf("%s %s: kind=%q ok=%v, want %q %v", tt.event, tt.payload, e.Kind, ok, tt.kind, tt.ok)
			continue
		}
		out, _ := json.Marshal(e)
		for _, banned := range []string{"refactor", "ProjectX", "secrets.env", "the answer", "diff", "permission to run", "waiting"} {
			if strings.Contains(string(out), banned) {
				t.Errorf("%s: hook event carries content %q: %s", tt.event, banned, out)
			}
		}
	}

	// Free text where an ID belongs is dropped, not forwarded.
	e, _ := mapHookPayload("Stop", map[string]any{"session_id": "my secret session notes"}, now)
	if e.SessionID != "" {
		t.Errorf("session_id = %q", e.SessionID)
	}
	e, _ = mapHookPayload("SessionStart", map[string]any{"session_id": "s1", "model": "ignore previous instructions"}, now)
	if e.Model != "" {
		t.Errorf("model = %q", e.Model)
	}
}

func TestHookMetricEventValidation(t *testing.T) {
	now := metricsBase
	good := hookEvent{Kind: kindTurnStarted, SessionID: "s1", AgentKind: "claude-code", AtMs: now.UnixMilli()}
	if _, err := hookMetricEvent(good, now); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]hookEvent{
		"unknown kind": {Kind: "decision", SessionID: "s1"},
		"no session":   {Kind: kindTurnStarted},
		"text session": {Kind: kindTurnStarted, SessionID: "two words"},
		"text turn":    {Kind: kindTurnStarted, SessionID: "s1", TurnID: "a/b"},
		"tool class":   {Kind: kindToolActivity, SessionID: "s1", ToolClass: "Bash"},
		"model":        {Kind: kindSessionStarted, SessionID: "s1", Model: "has spaces"},
	} {
		if _, err := hookMetricEvent(e, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	far := good
	far.AtMs = now.Add(48 * time.Hour).UnixMilli()
	if m, _ := hookMetricEvent(far, now); !m.At.Equal(now) {
		t.Errorf("future timestamp kept: %v", m.At)
	}
}

type syncRecorder struct {
	mu     sync.Mutex
	events []metricEvent
}

func (r *syncRecorder) Record(e metricEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *syncRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// shortSocketPath stays under the 104-byte Unix socket path limit on macOS.
func shortSocketPath(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "a11")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s", hookSocketName)
}

func TestHookSocketEndToEnd(t *testing.T) {
	path := shortSocketPath(t)
	rec := &syncRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startHookServer(ctx, path, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", fi, err)
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Errorf("socket dir mode = %v", di.Mode().Perm())
	}

	payload := `{"session_id":"s1","prompt_id":"p1","prompt":"leak this ProjectX plan"}`
	if code := runHookCLI([]string{"--socket", path, "UserPromptSubmit"}, strings.NewReader(payload), time.Now()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for i := 0; i < 100 && rec.len() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if rec.len() != 1 || rec.events[0].Kind != kindTurnStarted || rec.events[0].SessionID != "s1" {
		t.Fatalf("recorded %+v", rec.events)
	}

	// A second agent11 must not steal the socket.
	if err := startHookServer(ctx, path, rec, slog.Default()); err == nil || !strings.Contains(err.Error(), "another agent11") {
		t.Errorf("second server err = %v", err)
	}
	// Garbage and non-hook input never fails the agent.
	if code := runHookCLI([]string{"--socket", path}, strings.NewReader("not json"), time.Now()); code != 0 {
		t.Errorf("garbage exit %d", code)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	if code := runHookCLI([]string{"--socket", path, "Stop"}, strings.NewReader(`{"session_id":"s1"}`), time.Now()); code != 0 {
		t.Errorf("no listener exit %d", code)
	}
}

func TestHookSocketRefusesRegularFile(t *testing.T) {
	path := shortSocketPath(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("x"), 0o600)
	if err := startHookServer(context.Background(), path, nopRecorder{}, slog.Default()); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("err = %v", err)
	}
}

func life(min int, kind, session string) metricEvent {
	return metricEvent{At: at(min), Kind: kind, SessionID: session, AgentKind: "claude-code"}
}

func withReq(e metricEvent, req string) metricEvent { e.RequestID = req; return e }

func agentReport(t *testing.T, events []metricEvent, toMin int, nowMin int) agentMetrics {
	t.Helper()
	db := readOnly(t, writeMetrics(t, events))
	r, err := queryMetrics(db, metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(toMin).UnixMilli()}, defaultStallMs, at(nowMin))
	if err != nil {
		t.Fatal(err)
	}
	return r.Agents
}

func TestAgentLifecycleMetrics(t *testing.T) {
	start := life(0, kindSessionStarted, "s1")
	start.Model = "claude-opus-5-5"
	a := agentReport(t, []metricEvent{
		{At: at(0), Kind: kindAgentStarted},
		start,
		life(1, kindTurnStarted, "s1"),
		life(2, kindToolActivity, "s1"),
		life(3, kindApprovalRequested, "s1"),
		life(5, kindToolActivity, "s1"), // the approved tool runs: 2 minute wait
		life(7, kindTurnCompleted, "s1"),
		life(10, kindTurnStarted, "s1"),
		withReq(life(11, kindQuestionRequested, "s1"), "q1"),
		withReq(life(12, kindToolActivity, "s1"), "t9"),      // does not answer a question
		withReq(life(14, kindAttentionResolved, "s1"), "q1"), // 3 minute wait
		life(15, kindToolActivity, "s1"),
		life(40, kindToolActivity, "s1"), // 25 minutes of silence while working: a stall
		life(41, kindTurnCompleted, "s1"),
		life(42, kindSessionStarted, "s2"),
		life(43, kindTurnStarted, "s2"),
		life(44, kindAgentError, "s2"),
		life(50, kindSessionEnded, "s1"),
	}, 60, 60)

	min := func(n int64) int64 { return n * 60_000 }
	want := map[string]int64{"working": min(33), "blocked": min(5), "idle": min(14), "error": min(16), "unknown": 0}
	for k, v := range want {
		if a.TimeInStateMs[k] != v {
			t.Errorf("time_in_state[%s] = %d min, want %d", k, a.TimeInStateMs[k]/60_000, v/60_000)
		}
	}
	if a.BlockedMs["approval"] != min(2) || a.BlockedMs["question"] != min(3) {
		t.Errorf("blocked_ms = %v", a.BlockedMs)
	}
	if a.Turns.Started != 3 || a.Turns.Completed != 2 || a.Turns.Ambiguous != 0 || a.Turns.PerHour == nil || *a.Turns.PerHour != 3 {
		t.Errorf("turns = %+v", a.Turns)
	}
	o := a.OperatorResponse
	if o.WaitCount != 2 || o.WaitMs != min(5) || o.ByReason["approval"] != 1 || o.ByReason["question"] != 1 || o.Status != "available" || o.ResumeMs != nil {
		t.Errorf("operator_response = %+v", o)
	}
	if a.Errors.SessionFailure != 1 {
		t.Errorf("errors = %+v", a.Errors)
	}
	if len(a.Stalls) != 1 || a.Stalls[0].DurationMs != min(25) || a.Stalls[0].Ongoing || a.Stalls[0].SessionID != "s1" {
		t.Errorf("stalls = %+v", a.Stalls)
	}
	if a.Sessions.Started != 2 || a.Sessions.ByModel["claude-opus-5-5"] != 1 || a.Sessions.ByAgentKind["claude-code"] != 2 {
		t.Errorf("sessions = %+v", a.Sessions)
	}
}

func TestAgentLifecycleEdgeCases(t *testing.T) {
	// agent11 crashes while s1 waits on a question; the wait and the interval
	// are censored at the last event, not stretched over the downtime.
	a := agentReport(t, []metricEvent{
		{At: at(0), Kind: kindAgentStarted},
		life(1, kindTurnStarted, "s1"),
		withReq(life(2, kindQuestionRequested, "s1"), "q1"),
		{At: at(4), Kind: kindClipboard},
		{At: at(30), Kind: kindAgentStarted},
		life(31, kindTurnStarted, "s1"), // seen fresh after the restart
		life(32, kindTurnCompleted, "s1"),
	}, 60, 60)
	if a.OperatorResponse.WaitCount != 0 || a.OperatorResponse.Censored != 1 || a.Censored != 1 {
		t.Errorf("crash: waits=%d censored=%d intervals=%d", a.OperatorResponse.WaitCount, a.OperatorResponse.Censored, a.Censored)
	}
	// Working 1-2 and 31-32, blocked 2-4 (cut at the clipboard event, the last
	// sign of life), nothing counted for the 26 minutes agent11 was down.
	if a.TimeInStateMs["working"] != 2*60_000 || a.TimeInStateMs["blocked"] != 2*60_000 || a.BlockedMs["question"] != 2*60_000 ||
		a.TimeInStateMs["unknown"] != 0 || a.TimeInStateMs["idle"] != 28*60_000 {
		t.Errorf("crash time_in_state = %v", a.TimeInStateMs)
	}

	// Duplicate approval signals for one prompt make one wait; a new prompt
	// while working is an ambiguous turn (Claude sends no Stop on interrupt).
	a = agentReport(t, []metricEvent{
		life(0, kindTurnStarted, "s1"),
		life(1, kindApprovalRequested, "s1"),
		withReq(life(1, kindApprovalRequested, "s1"), "t1"),
		life(2, kindToolActivity, "s1"),
		life(3, kindTurnStarted, "s1"),
		life(4, kindTurnCompleted, "s1"),
	}, 60, 60)
	if a.OperatorResponse.WaitCount != 1 || a.Turns.Ambiguous != 1 || a.Turns.Started != 2 {
		t.Errorf("dupes: waits=%d ambiguous=%d started=%d", a.OperatorResponse.WaitCount, a.Turns.Ambiguous, a.Turns.Started)
	}

	// Working with no evidence since minute 5 is an ongoing stall at minute 60.
	a = agentReport(t, []metricEvent{
		life(0, kindTurnStarted, "s1"),
		life(5, kindToolActivity, "s1"),
	}, 60, 60)
	if len(a.Stalls) != 1 || !a.Stalls[0].Ongoing || a.Stalls[0].DurationMs != 55*60_000 {
		t.Errorf("ongoing stall = %+v", a.Stalls)
	}
}

func TestLaunchesAndResources(t *testing.T) {
	dec := func(model, provider string) metricEvent {
		return metricEvent{At: at(5), Kind: kindDecision, Verdict: "allow", Model: model, Provider: provider}
	}
	db := readOnly(t, writeMetrics(t, []metricEvent{
		{At: at(1), Kind: kindAIAppStarted, App: "Cursor", Mode: "initial"}, // already running: not a launch
		{At: at(2), Kind: kindAIAppStarted, App: "ChatGPT"},
		dec("claude-opus-5-5", "anthropic"), dec("claude-opus-5-5", "anthropic"), dec("gpt-5", "openai"),
		{At: at(6), Kind: kindResource, App: "Cursor", CPUPct: 10, CPUMax: 40, RSSKB: 512 * 1024, Procs: 9},
		{At: at(7), Kind: kindResource, App: "Cursor", CPUPct: 20, CPUMax: 30, RSSKB: 1024 * 1024, Procs: 11},
	}))
	r, err := queryMetrics(db, metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}, defaultStallMs, at(60))
	if err != nil {
		t.Fatal(err)
	}
	l := r.Launches
	if l.AppStarts["ChatGPT"] != 1 || l.AppStarts["Cursor"] != 0 || l.RequestsByModel["claude-opus-5-5"] != 2 || l.RequestsByProvider["openai"] != 1 {
		t.Errorf("launches = %+v", l)
	}
	if u := r.Resources["Cursor"]; u != (resourceUsage{Samples: 2, CPUAvg: 15, CPUPeak: 40, RSSAvgMB: 768, RSSPeakMB: 1024, ProcsPeak: 11}) {
		t.Errorf("resources = %+v", u)
	}

	f := metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli(), Model: "gpt-5"}
	if r, _ = queryMetrics(db, f, defaultStallMs, at(60)); r.Decisions.Total != 1 {
		t.Errorf("model filter total = %d", r.Decisions.Total)
	}
}

func TestResourceSampling(t *testing.T) {
	rec := &captureRecorder{}
	w := newAIWatcher(slog.Default())
	w.rec = rec
	w.resStart = metricsBase
	w.sample("Cursor", []process{{cpu: 10, rssKB: 100}, {cpu: 30, rssKB: 300}})
	w.sample("Cursor", []process{{cpu: 20, rssKB: 500}})
	w.flushResources(metricsBase.Add(30 * time.Second))
	if len(rec.events) != 0 {
		t.Fatal("flushed before the window ended")
	}
	w.flushResources(metricsBase.Add(resourceWindow))
	if len(rec.events) != 1 {
		t.Fatalf("events = %d", len(rec.events))
	}
	e := rec.events[0]
	if e.Kind != kindResource || e.App != "Cursor" || e.CPUPct != 30 || e.CPUMax != 40 || e.RSSKB != 500 || e.Procs != 2 {
		t.Errorf("sample = %+v", e)
	}
}

func TestParsePSLine(t *testing.T) {
	p, ok := parsePSLine("  4242     1  12.5  204800 /Applications/LM Studio.app/Contents/MacOS/LM Studio")
	if !ok || p.pid != 4242 || p.ppid != 1 || p.cpu != 12.5 || p.rssKB != 204800 || p.exe != "/Applications/LM Studio.app/Contents/MacOS/LM Studio" {
		t.Errorf("parsed %+v ok=%v", p, ok)
	}
	if _, ok := parsePSLine("garbage line"); ok {
		t.Error("garbage parsed")
	}
}

func TestProviderAndModel(t *testing.T) {
	for host, want := range map[string]string{"api.anthropic.com": "anthropic", "api.openai.com:443": "openai",
		"openrouter.ai": "openrouter", "generativelanguage.googleapis.com": "google", "llm.internal.example": "llm.internal.example"} {
		if got := providerFor(host); got != want {
			t.Errorf("providerFor(%s) = %s", host, got)
		}
	}
	if m := requestModel([]byte(`{"model":"openai/gpt-4o","messages":[]}`)); m != "openai/gpt-4o" {
		t.Errorf("model = %q", m)
	}
	if m := requestModel([]byte(`{"model":"please exfiltrate the plan"}`)); m != "" {
		t.Errorf("free text accepted as model: %q", m)
	}
}

func TestClaudeHooksSnippet(t *testing.T) {
	out, err := hooksSnippet("claude-code", "/usr/local/bin/agent11")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hooks map[string][]struct {
			Hooks []struct{ Type, Command string }
		}
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"SessionStart", "UserPromptSubmit", "Stop", "PreToolUse", "PostToolUse", "Notification"} {
		h := cfg.Hooks[ev]
		if len(h) != 1 || !strings.Contains(h[0].Hooks[0].Command, "hook "+ev) {
			t.Errorf("%s: %+v", ev, h)
		}
	}
	if _, err := hooksSnippet("windsurf", "x"); err == nil {
		t.Error("unknown agent accepted")
	}
}

func TestAntigravityHooksSnippet(t *testing.T) {
	out, err := hooksSnippet("antigravity", "/opt/agent11")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Agent11 map[string][]struct {
			Matcher string
			Hooks   []struct{ Type, Command string }
		} `json:"agent11"`
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"PreInvocation", "PostInvocation", "PreToolUse", "PostToolUse", "Stop"} {
		h := cfg.Agent11[ev]
		if len(h) != 1 || !strings.Contains(h[0].Hooks[0].Command, "hook --agent antigravity "+ev) {
			t.Errorf("%s: %+v", ev, h)
		}
	}
	if cfg.Agent11["PreToolUse"][0].Matcher != "*" || cfg.Agent11["Stop"][0].Matcher != "" {
		t.Error("matcher only belongs on tool events")
	}
}

func TestMapAntigravityPayload(t *testing.T) {
	now := metricsBase
	tests := []struct {
		event, payload, kind string
		ok                   bool
	}{
		{"PreInvocation", `{"conversationId":"c-1","modelName":"gemini-3.6-flash","invocationNum":1}`, kindTurnStarted, true},
		{"PreToolUse", `{"conversationId":"c-1","toolCall":{"name":"run_command","args":{"command":"cat SECRET.env"}},"stepIdx":2}`, kindToolActivity, true},
		{"PostToolUse", `{"conversationId":"c-1","toolCall":{"name":"read_file","args":{"path":"/secret/path"}}}`, kindToolActivity, true},
		{"PostInvocation", `{"conversationId":"c-1"}`, kindAgentObservation, true},
		{"Stop", `{"conversationId":"c-1","terminationReason":"done","fullyIdle":true}`, kindTurnCompleted, true},
		{"Stop", `{"conversationId":"c-1","error":"model overloaded"}`, kindAgentError, true},
		{"UnknownEvent", `{"conversationId":"c-1"}`, "", false},
	}
	for _, tt := range tests {
		var obj map[string]any
		if err := json.Unmarshal([]byte(tt.payload), &obj); err != nil {
			t.Fatal(err)
		}
		e, ok := mapAntigravityPayload(tt.event, obj, now)
		if ok != tt.ok || (ok && e.Kind != tt.kind) {
			t.Errorf("%s: kind=%q ok=%v, want %q %v", tt.event, e.Kind, ok, tt.kind, tt.ok)
		}
		if ok && (e.AgentKind != "antigravity" || e.SessionID != "c-1") {
			t.Errorf("%s: agentKind=%q session=%q", tt.event, e.AgentKind, e.SessionID)
		}
		out, _ := json.Marshal(e)
		for _, banned := range []string{"SECRET.env", "/secret/path", "run_command", "read_file", "overloaded"} {
			if strings.Contains(string(out), banned) {
				t.Errorf("%s: antigravity event carries %q: %s", tt.event, banned, out)
			}
		}
	}
	// mapAgentPayload routes by agent name.
	e, ok := mapAgentPayload("antigravity", "PreInvocation", map[string]any{"conversationId": "c-9", "modelName": "gemini-3.6-pro"}, now)
	if !ok || e.Kind != kindTurnStarted || e.Model != "gemini-3.6-pro" {
		t.Errorf("dispatch: %+v ok=%v", e, ok)
	}
	if _, ok := mapAgentPayload("windsurf", "PreInvocation", map[string]any{}, now); ok {
		t.Error("unknown agent routed")
	}
}

func TestAntigravitySessionInMetrics(t *testing.T) {
	// No session_started event: the session is keyed on conversationId and
	// must still show up by agent kind and model.
	ev := func(min int, kind, conv, model string) metricEvent {
		return metricEvent{At: at(min), Kind: kind, SessionID: conv, AgentKind: "antigravity", Model: model}
	}
	a := agentReport(t, []metricEvent{
		{At: at(0), Kind: kindAgentStarted},
		ev(1, kindTurnStarted, "c-1", "gemini-3.6-flash"),
		ev(2, kindToolActivity, "c-1", "gemini-3.6-flash"),
		ev(3, kindTurnCompleted, "c-1", "gemini-3.6-flash"),
	}, 60, 60)
	if a.Sessions.Started != 0 || a.Sessions.Seen != 1 || a.Sessions.ByAgentKind["antigravity"] != 1 || a.Sessions.ByModel["gemini-3.6-flash"] != 1 {
		t.Errorf("antigravity sessions = %+v", a.Sessions)
	}
	if a.Turns.Started != 1 || a.Turns.Completed != 1 {
		t.Errorf("turns = %+v", a.Turns)
	}
	if a.TimeInStateMs["working"] != 2*60_000 {
		t.Errorf("working = %d", a.TimeInStateMs["working"])
	}
}

var _ net.Conn // keep net imported for the socket helpers above
