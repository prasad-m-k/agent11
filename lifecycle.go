package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Agent lifecycle capture, modeled on c11's Claude hook mapping. Claude Code
// runs "agent11 hook" on each hook event; the command keeps only the event
// name and opaque IDs from the hook payload (never the prompt, tool input,
// tool output, or message text) and posts that to agent11 over a Unix socket
// that only this user can open. The query side folds these events into
// time-in-state, turns, blocked time, operator waits, errors, and stalls.

// Lifecycle kinds stored in the metrics events table.
const (
	kindSessionStarted    = "agent_session_started"
	kindSessionEnded      = "agent_session_ended"
	kindTurnStarted       = "agent_turn_started"
	kindTurnCompleted     = "agent_turn_completed"
	kindQuestionRequested = "agent_question_requested"
	kindPlanReviewRequest = "agent_plan_review_requested"
	kindApprovalRequested = "agent_approval_requested"
	kindAttentionResolved = "agent_attention_resolved"
	kindToolActivity      = "agent_tool_activity"
	kindAgentError        = "agent_error"
	kindChildSpawned      = "agent_child_spawned"
	kindChildCompleted    = "agent_child_completed"
	kindAgentObservation  = "agent_observation"
	hookAgentKindClaude   = "claude-code"
	hookAgentKindAntigrav = "antigravity"
	hookToolAskUser       = "ask_user_question"
	hookToolExitPlan      = "exit_plan_mode"
	hookToolOther         = "other"
	hookMaxPayload        = 1 << 20 // hook stdin can carry a whole tool output; read it, keep none of it
	hookMaxEventBytes     = 4 << 10
	hookClientTimeout     = time.Second
	hookSocketName        = "hooks.sock"
)

var lifecycleKinds = []string{kindSessionStarted, kindSessionEnded, kindTurnStarted, kindTurnCompleted,
	kindQuestionRequested, kindPlanReviewRequest, kindApprovalRequested, kindAttentionResolved,
	kindToolActivity, kindAgentError, kindChildSpawned, kindChildCompleted, kindAgentObservation}

// hookEvent is everything that leaves the hook command. Each string is an
// opaque ID or a fixed name; mapHookPayload drops anything else.
type hookEvent struct {
	Kind      string `json:"kind"`
	AgentKind string `json:"agent_kind"`
	SessionID string `json:"session_id,omitempty"`
	TurnID    string `json:"turn_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	ToolClass string `json:"tool_class,omitempty"`
	Model     string `json:"model,omitempty"`
	AtMs      int64  `json:"at_ms"`
}

// opaqueID is c11's rule: printable ASCII without spaces or slashes, at most
// 128 bytes. Anything else, such as free text, becomes absent.
func opaqueID(v any) string {
	s, _ := v.(string)
	if s == "" || len(s) > 128 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 33 || c > 126 || c == '/' || c == '\\' {
			return ""
		}
	}
	return s
}

// modelName allows the characters model IDs use, including "/" for
// provider-prefixed IDs such as "openai/gpt-4o" on OpenRouter.
var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)

func cleanModel(v any) string {
	s, _ := v.(string)
	if !modelName.MatchString(s) {
		return ""
	}
	return s
}

// mapHookPayload turns a Claude Code hook payload into a hookEvent, or
// reports false for events with no lifecycle meaning. event is the hook
// name; when empty, the payload's hook_event_name is used.
func mapHookPayload(event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	if event == "" {
		event, _ = obj["hook_event_name"].(string)
	}
	tool, _ := obj["tool_name"].(string)
	e := hookEvent{AgentKind: hookAgentKindClaude, SessionID: opaqueID(obj["session_id"]),
		TurnID: opaqueID(obj["prompt_id"]), AtMs: now.UnixMilli()}
	toolClass := func() string {
		switch tool {
		case "AskUserQuestion":
			return hookToolAskUser
		case "ExitPlanMode":
			return hookToolExitPlan
		}
		return hookToolOther
	}
	switch strings.ToLower(strings.ReplaceAll(event, "-", "")) {
	case "sessionstart":
		e.Kind, e.Model = kindSessionStarted, cleanModel(obj["model"])
	case "sessionend":
		e.Kind, e.TurnID = kindSessionEnded, "" // a later prompt's ID would look stale here (c11 does the same)
	case "userpromptsubmit":
		e.Kind = kindTurnStarted
	case "stop":
		e.Kind = kindTurnCompleted
	case "stopfailure":
		e.Kind = kindAgentError
	case "pretooluse":
		e.RequestID, e.ToolClass = opaqueID(obj["tool_use_id"]), toolClass()
		switch e.ToolClass {
		case hookToolAskUser:
			e.Kind = kindQuestionRequested
		case hookToolExitPlan:
			e.Kind = kindPlanReviewRequest
		default:
			e.Kind = kindToolActivity
		}
	case "posttooluse":
		e.RequestID, e.ToolClass = opaqueID(obj["tool_use_id"]), toolClass()
		if e.ToolClass != hookToolOther {
			if e.RequestID == "" {
				return e, false // an answer that cannot be tied to its question proves nothing
			}
			e.Kind = kindAttentionResolved
		} else {
			e.Kind = kindToolActivity
		}
	case "permissionrequest":
		e.RequestID, e.ToolClass = opaqueID(obj["tool_use_id"]), toolClass()
		if e.ToolClass != hookToolOther {
			return e, false // the question or plan review already blocked on PreToolUse
		}
		e.Kind = kindApprovalRequested
	case "notification":
		if t, _ := obj["notification_type"].(string); t == "permission_prompt" {
			e.Kind = kindApprovalRequested
		} else {
			e.Kind = kindAgentObservation
		}
	case "subagentstart":
		e.Kind = kindChildSpawned
	case "subagentstop":
		e.Kind = kindChildCompleted
	default:
		return e, false
	}
	return e, true
}

// mapAgentPayload dispatches to the mapper for the named agent. Claude Code is
// the default so an existing "agent11 hook <Event>" config keeps working.
func mapAgentPayload(agent, event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	switch agent {
	case "", hookAgentKindClaude:
		return mapHookPayload(event, obj, now)
	case hookAgentKindAntigrav:
		return mapAntigravityPayload(event, obj, now)
	default:
		if a := customAdapters[agent]; a != nil {
			return mapWithAdapter(a, event, obj, now.UnixMilli())
		}
		return hookEvent{}, false
	}
}

// customAdapters holds declarative agents loaded from the adapters directory.
// It is populated by the short-lived "agent11 hook" and "--print-config"
// invocations; the collector and hook server never map, so no locking is needed.
var customAdapters = map[string]*HookAdapter{}

// loadCustomAdapters merges the adapters directory into the registry.
func loadCustomAdapters(dir string) []error {
	loaded, errs := loadAdapterDir(dir)
	for name, a := range loaded {
		customAdapters[name] = a
	}
	return errs
}

// knownAgents lists every agent that can be hooked: the built-ins plus any
// loaded custom adapters.
func knownAgents() []string {
	out := []string{hookAgentKindClaude, hookAgentKindAntigrav}
	for name := range customAdapters {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// mapAntigravityPayload turns a Google Antigravity hook payload into a
// hookEvent. Antigravity has no session start/end event, so the session is
// keyed on conversationId and first-seen marks it. toolCall.args,
// transcriptPath, workspacePaths and the artifact directory are content or
// paths and are never read. modelName rides on every event.
func mapAntigravityPayload(event string, obj map[string]any, now time.Time) (hookEvent, bool) {
	e := hookEvent{AgentKind: hookAgentKindAntigrav, SessionID: opaqueID(obj["conversationId"]),
		Model: cleanModel(obj["modelName"]), AtMs: now.UnixMilli()}
	switch strings.ToLower(strings.ReplaceAll(event, "-", "")) {
	case "preinvocation":
		e.Kind = kindTurnStarted
	case "postinvocation":
		e.Kind = kindAgentObservation
	case "pretooluse":
		e.Kind, e.ToolClass = kindToolActivity, hookToolOther
	case "posttooluse":
		e.Kind, e.ToolClass = kindToolActivity, hookToolOther
	case "stop":
		// terminationReason/error values are not documented; treat any error
		// string as a session failure, otherwise a completed turn.
		if s, _ := obj["error"].(string); s != "" {
			e.Kind = kindAgentError
		} else {
			e.Kind = kindTurnCompleted
		}
	default:
		return e, false
	}
	return e, true
}

// defaultHookSocket sits beside the metrics database, in the same 0700 directory.
func defaultHookSocket() string {
	return filepath.Join(filepath.Dir(defaultMetricsPath()), hookSocketName)
}

// runHookCLI is "agent11 hook [event]". It must never get in the agent's way:
// it prints nothing (some hook outputs are fed back to the model), always
// exits 0, and gives up after a second if agent11 is not listening.
func runHookCLI(args []string, stdin io.Reader, now time.Time) int {
	socket := defaultHookSocket()
	adaptersDir := defaultAdaptersDir()
	agent, event := hookAgentKindClaude, ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--socket" && i+1 < len(args):
			socket = args[i+1]
			i++
		case args[i] == "--agent" && i+1 < len(args):
			agent = args[i+1]
			i++
		case args[i] == "--adapters" && i+1 < len(args):
			adaptersDir = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-"):
			event = args[i]
		}
	}
	if agent != hookAgentKindClaude && agent != hookAgentKindAntigrav {
		loadCustomAdapters(adaptersDir) // errors ignored: the hook must stay silent and never fail the agent
	}
	var obj map[string]any
	if err := json.NewDecoder(io.LimitReader(stdin, hookMaxPayload)).Decode(&obj); err != nil {
		return 0
	}
	e, ok := mapAgentPayload(agent, event, obj, now)
	if !ok {
		return 0
	}
	body, _ := json.Marshal(e)
	ctx, cancel := context.WithTimeout(context.Background(), hookClientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent11/hook", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	if resp, err := client.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return 0
}

// startHookServer listens on a Unix socket created 0600 in a 0700 directory,
// so only this user's processes can post lifecycle events.
func startHookServer(ctx context.Context, path string, rec recorder, logger *slog.Logger) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("hook socket dir: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return fmt.Errorf("hook socket %s: exists and is not a socket", path)
		}
		// A socket left by an earlier run. If something still answers on it,
		// another agent11 owns it.
		if c, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
			c.Close()
			return fmt.Errorf("hook socket %s: another agent11 is listening", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("hook socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("hook socket: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var e hookEvent
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, hookMaxEventBytes)).Decode(&e); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		m, err := hookMetricEvent(e, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.Record(m)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	logger.Info("hook socket listening", "path", path)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
		os.Remove(path)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hookMetricEvent re-validates what arrives on the socket: any local process
// of this user can post, so the server applies the same rules as the client.
func hookMetricEvent(e hookEvent, now time.Time) (metricEvent, error) {
	if !slices.Contains(lifecycleKinds, e.Kind) {
		return metricEvent{}, fmt.Errorf("unknown kind %q", e.Kind)
	}
	if e.SessionID == "" || opaqueID(e.SessionID) != e.SessionID {
		return metricEvent{}, errors.New("session_id must be an opaque ID")
	}
	for _, v := range []string{e.AgentKind, e.TurnID, e.RequestID} {
		if v != "" && opaqueID(v) != v {
			return metricEvent{}, errors.New("IDs must be opaque")
		}
	}
	if e.ToolClass != "" && e.ToolClass != hookToolAskUser && e.ToolClass != hookToolExitPlan && e.ToolClass != hookToolOther {
		return metricEvent{}, errors.New("unknown tool_class")
	}
	if e.Model != "" && cleanModel(e.Model) != e.Model {
		return metricEvent{}, errors.New("bad model")
	}
	at := time.UnixMilli(e.AtMs)
	// Trust the hook's clock only near ours, as c11 bounds emitted times.
	if e.AtMs == 0 || at.Before(now.Add(-24*time.Hour)) || at.After(now.Add(5*time.Minute)) {
		at = now
	}
	agentKind := e.AgentKind
	if agentKind == "" {
		agentKind = hookAgentKindClaude
	}
	return metricEvent{At: at, Kind: e.Kind, SessionID: e.SessionID, AgentKind: agentKind, TurnID: e.TurnID,
		RequestID: e.RequestID, ToolClass: e.ToolClass, Model: e.Model}, nil
}

// providerFor names the LLM provider behind an upstream host; unknown hosts
// are reported as themselves.
func providerFor(host string) string {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, p := range []struct{ suffix, name string }{
		{"anthropic.com", "anthropic"}, {"openai.com", "openai"}, {"openrouter.ai", "openrouter"},
		{"googleapis.com", "google"}, {"mistral.ai", "mistral"}, {"x.ai", "xai"},
		{"deepseek.com", "deepseek"}, {"groq.com", "groq"}, {"cohere.com", "cohere"},
		{"cohere.ai", "cohere"}, {"together.xyz", "together"}, {"fireworks.ai", "fireworks"},
		{"azure.com", "azure"},
	} {
		if host == p.suffix || strings.HasSuffix(host, "."+p.suffix) {
			return p.name
		}
	}
	return host
}

// requestModel reads the top-level "model" field of an LLM request body. It
// is a name, not content, and is dropped unless it looks like one.
func requestModel(body []byte) string {
	var v struct {
		Model any `json:"model"`
	}
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	return cleanModel(v.Model)
}

// hookConfigDest says where the named agent's config fragment belongs.
func hookConfigDest(agent string) string {
	switch agent {
	case hookAgentKindAntigrav:
		return "Antigravity: write to a workspace .agents/hooks.json or the global ~/.gemini/config/hooks.json"
	case "", hookAgentKindClaude:
		return "Claude Code: merge the \"hooks\" object into ~/.claude/settings.json"
	default:
		if a := customAdapters[agent]; a != nil {
			return a.configDest()
		}
		return ""
	}
}

// hooksSnippet returns the config fragment that wires every lifecycle hook for
// the named agent to this binary.
func hooksSnippet(agent, binary string) (string, error) {
	switch agent {
	case "", hookAgentKindClaude:
		return claudeHooksSnippet(binary), nil
	case hookAgentKindAntigrav:
		return antigravityHooksSnippet(binary), nil
	default:
		if a := customAdapters[agent]; a != nil {
			return renderHookConfig(a, binary), nil
		}
		return "", fmt.Errorf("unknown agent %q; known: %s", agent, strings.Join(knownAgents(), ", "))
	}
}

// claudeHooksSnippet is the settings.json fragment for Claude Code. Merge its
// "hooks" into ~/.claude/settings.json.
func claudeHooksSnippet(binary string) string {
	events := []string{"SessionStart", "SessionEnd", "UserPromptSubmit", "Stop", "StopFailure",
		"PreToolUse", "PostToolUse", "PermissionRequest", "Notification", "SubagentStart", "SubagentStop"}
	hooks := map[string]any{}
	for _, ev := range events {
		hooks[ev] = []any{map[string]any{"hooks": []any{map[string]any{
			"type": "command", "command": fmt.Sprintf("%q hook %s", binary, ev), "timeout": 5}}}}
	}
	out, _ := json.MarshalIndent(map[string]any{"hooks": hooks}, "", "  ")
	return string(out)
}

// antigravityHooksSnippet is the hooks.json for Google Antigravity. Write it to
// a workspace .agents/hooks.json or the global ~/.gemini/config/hooks.json.
// Tool events carry a "*" matcher so every tool is seen.
func antigravityHooksSnippet(binary string) string {
	toolEvents := map[string]bool{"PreToolUse": true, "PostToolUse": true}
	entries := map[string]any{}
	for _, ev := range []string{"PreInvocation", "PostInvocation", "PreToolUse", "PostToolUse", "Stop"} {
		hook := map[string]any{"type": "command",
			"command": fmt.Sprintf("%q hook --agent %s %s", binary, hookAgentKindAntigrav, ev), "timeout": 5}
		entry := map[string]any{"hooks": []any{hook}}
		if toolEvents[ev] {
			entry["matcher"] = "*"
		}
		entries[ev] = []any{entry}
	}
	out, _ := json.MarshalIndent(map[string]any{"agent11": entries}, "", "  ")
	return string(out)
}
