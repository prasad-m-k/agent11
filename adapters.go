package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// A hook adapter describes, as data, how one agent tool's hook payload maps to
// agent11 lifecycle events. The two built-in agents (claude-code, antigravity)
// are hand-written Go in lifecycle.go for their quirks; every other agent is
// added by dropping a JSON adapter file in the adapters directory, with no
// recompile. The format below is deliberately small: a field map, an
// event-to-kind table, and a few per-event rules that cover the common cases.
//
// Example (tool "mycoder" whose hook sends JSON on stdin and takes the event
// name as the last argument):
//
//	{
//	  "name": "mycoder",
//	  "config_style": "args",
//	  "fields": { "session": "sessionId", "turn": "turnId", "request": "callId",
//	              "model": "model", "tool": "toolName" },
//	  "tool_classes": { "AskHuman": "ask_user_question", "ReviewPlan": "exit_plan_mode" },
//	  "events": {
//	    "start":   { "kind": "agent_session_started" },
//	    "prompt":  { "kind": "agent_turn_started" },
//	    "tool":    { "kind": "agent_tool_activity", "use_request": true,
//	                 "by_tool_class": { "ask_user_question": "agent_question_requested" } },
//	    "tool_end":{ "kind": "agent_attention_resolved", "use_request": true,
//	                 "require_request_for_classes": ["ask_user_question"] },
//	    "stop":    { "kind": "agent_turn_completed",
//	                 "by_field": { "field": "error", "present": "agent_error" } }
//	  }
//	}

// HookAdapter is one agent's declarative mapping.
type HookAdapter struct {
	Name        string                  `json:"name"`
	ConfigStyle string                  `json:"config_style"` // args, claude, or antigravity
	Fields      map[string]string       `json:"fields"`       // keys: session, turn, request, model, tool
	ToolClasses map[string]string       `json:"tool_classes"` // tool name -> ask_user_question | exit_plan_mode | other
	Events      map[string]*adapterRule `json:"events"`       // key = the hook event name, as the tool emits it

	norm map[string]*adapterRule // event name normalized -> rule
}

type adapterRule struct {
	Kind                     string            `json:"kind"`
	Matcher                  string            `json:"matcher,omitempty"` // antigravity/claude tool matcher in the generated config
	UseRequest               bool              `json:"use_request,omitempty"`
	ClearTurn                bool              `json:"clear_turn,omitempty"`
	ByToolClass              map[string]string `json:"by_tool_class,omitempty"`
	RequireRequestForClasses []string          `json:"require_request_for_classes,omitempty"`
	DropForClasses           []string          `json:"drop_for_classes,omitempty"`
	ByField                  *byFieldRule      `json:"by_field,omitempty"`
}

// byFieldRule overrides the kind from another payload field: Present sets a
// kind when the field is a non-empty string, Map sets a kind per field value.
type byFieldRule struct {
	Field   string            `json:"field"`
	Present string            `json:"present,omitempty"`
	Map     map[string]string `json:"map,omitempty"`
}

var validConfigStyles = []string{"args", "claude", "antigravity"}

func normEvent(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
}

// compile validates an adapter and builds its normalized event lookup.
func (a *HookAdapter) compile() error {
	if a.Name == "" {
		return fmt.Errorf("adapter: field %q is required", "name")
	}
	if a.Name == hookAgentKindClaude || a.Name == hookAgentKindAntigrav {
		return fmt.Errorf("adapter %q: name is reserved for a built-in agent", a.Name)
	}
	if opaqueID(a.Name) != a.Name {
		return fmt.Errorf("adapter %q: name must be an opaque token (no spaces or slashes)", a.Name)
	}
	if a.ConfigStyle == "" {
		a.ConfigStyle = "args"
	}
	if !slices.Contains(validConfigStyles, a.ConfigStyle) {
		return fmt.Errorf("adapter %q: config_style %q is not one of %s", a.Name, a.ConfigStyle, strings.Join(validConfigStyles, ", "))
	}
	if a.Fields["session"] == "" {
		return fmt.Errorf("adapter %q: fields.session is required", a.Name)
	}
	for tool, class := range a.ToolClasses {
		if class != hookToolAskUser && class != hookToolExitPlan && class != hookToolOther {
			return fmt.Errorf("adapter %q: tool_classes[%q] = %q is not a known tool class", a.Name, tool, class)
		}
	}
	if len(a.Events) == 0 {
		return fmt.Errorf("adapter %q: at least one event is required", a.Name)
	}
	a.norm = map[string]*adapterRule{}
	for ev, rule := range a.Events {
		if rule == nil {
			return fmt.Errorf("adapter %q: event %q has no rule", a.Name, ev)
		}
		kinds := append([]string{rule.Kind}, rule.ByField.kinds()...)
		for _, k := range rule.ByToolClass {
			kinds = append(kinds, k)
		}
		for _, k := range kinds {
			if !slices.Contains(lifecycleKinds, k) {
				return fmt.Errorf("adapter %q: event %q uses unknown kind %q", a.Name, ev, k)
			}
		}
		if n := normEvent(ev); a.norm[n] != nil {
			return fmt.Errorf("adapter %q: event %q collides with another after normalizing", a.Name, ev)
		} else {
			a.norm[n] = rule
		}
	}
	return nil
}

func (b *byFieldRule) kinds() []string {
	if b == nil {
		return nil
	}
	out := []string{}
	if b.Present != "" {
		out = append(out, b.Present)
	}
	for _, k := range b.Map {
		out = append(out, k)
	}
	return out
}

// mapWithAdapter maps a hook payload to a hookEvent using the adapter. It is
// the declarative counterpart of mapHookPayload / mapAntigravityPayload.
func mapWithAdapter(a *HookAdapter, event string, obj map[string]any, now int64) (hookEvent, bool) {
	rule := a.norm[normEvent(event)]
	if rule == nil {
		return hookEvent{}, false
	}
	str := func(key string) string {
		if key == "" {
			return ""
		}
		s, _ := obj[key].(string)
		return s
	}
	e := hookEvent{AgentKind: a.Name, AtMs: now,
		SessionID: opaqueID(str(a.Fields["session"])), Model: cleanModel(str(a.Fields["model"]))}
	if !rule.ClearTurn {
		e.TurnID = opaqueID(str(a.Fields["turn"]))
	}
	tool := str(a.Fields["tool"])
	if tool != "" {
		if c, ok := a.ToolClasses[tool]; ok {
			e.ToolClass = c
		} else {
			e.ToolClass = hookToolOther
		}
	}
	if rule.UseRequest {
		e.RequestID = opaqueID(str(a.Fields["request"]))
	}
	e.Kind = rule.Kind
	if e.ToolClass != "" {
		if k, ok := rule.ByToolClass[e.ToolClass]; ok {
			e.Kind = k
		}
	}
	if b := rule.ByField; b != nil {
		v, _ := obj[b.Field].(string)
		if k, ok := b.Map[v]; ok && v != "" {
			e.Kind = k
		} else if b.Present != "" && v != "" {
			e.Kind = b.Present
		}
	}
	if e.ToolClass != "" && slices.Contains(rule.DropForClasses, e.ToolClass) {
		return e, false
	}
	if e.ToolClass != "" && slices.Contains(rule.RequireRequestForClasses, e.ToolClass) && e.RequestID == "" {
		return e, false
	}
	return e, true
}

// renderHookConfig builds the config fragment for a custom adapter. "args" and
// "claude" use the Claude settings.json shape; "antigravity" uses its hooks.json.
func renderHookConfig(a *HookAdapter, binary string) string {
	events := make([]string, 0, len(a.Events))
	for ev := range a.Events {
		events = append(events, ev)
	}
	sort.Strings(events)
	cmd := func(ev string) string { return fmt.Sprintf("%q hook --agent %s %s", binary, a.Name, ev) }

	if a.ConfigStyle == "antigravity" {
		entries := map[string]any{}
		for _, ev := range events {
			entry := map[string]any{"hooks": []any{map[string]any{"type": "command", "command": cmd(ev), "timeout": 5}}}
			if a.Events[ev].Matcher != "" {
				entry["matcher"] = a.Events[ev].Matcher
			}
			entries[ev] = []any{entry}
		}
		out, _ := json.MarshalIndent(map[string]any{"agent11": entries}, "", "  ")
		return string(out)
	}
	hooks := map[string]any{}
	for _, ev := range events {
		entry := map[string]any{"hooks": []any{map[string]any{"type": "command", "command": cmd(ev), "timeout": 5}}}
		if a.Events[ev].Matcher != "" {
			entry["matcher"] = a.Events[ev].Matcher
		}
		hooks[ev] = []any{entry}
	}
	out, _ := json.MarshalIndent(map[string]any{"hooks": hooks}, "", "  ")
	return string(out)
}

func (a *HookAdapter) configDest() string {
	if a.ConfigStyle == "antigravity" {
		return fmt.Sprintf("%s: write to the tool's hooks.json (workspace or global)", a.Name)
	}
	return fmt.Sprintf("%s: merge the \"hooks\" object into the tool's hook settings file", a.Name)
}

// defaultAdaptersDir sits beside the metrics database. Drop <name>.json files
// here to teach agent11 a new agent.
func defaultAdaptersDir() string {
	return filepath.Join(filepath.Dir(defaultMetricsPath()), "adapters")
}

// loadAdapterDir reads every *.json adapter in dir. A missing directory is not
// an error (there simply are no custom agents). Per-file problems are returned
// so the CLI can warn without failing.
func loadAdapterDir(dir string) (map[string]*HookAdapter, []error) {
	out := map[string]*HookAdapter{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, []error{fmt.Errorf("adapters dir: %w", err)}
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var a HookAdapter
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		if err := a.compile(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name(), err))
			continue
		}
		out[a.Name] = &a
	}
	return out, errs
}
