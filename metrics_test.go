package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var metricsBase = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func at(min int) time.Time { return metricsBase.Add(time.Duration(min) * time.Minute) }

// writeMetrics records events into a fresh store, closes it so every batch is
// committed, and returns the database path.
func writeMetrics(t *testing.T, events []metricEvent) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent11", "metrics.sqlite3")
	s, err := openMetricsStore(path, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		s.Record(e)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func readOnly(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := openMetricsDB(path, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func sampleEvents() []metricEvent {
	dec := func(min int, verdict string, enforced bool, class, rule, dest string, lat time.Duration) metricEvent {
		e := metricEvent{At: at(min), Kind: kindDecision, Verdict: verdict, Applied: "allow", Enforced: enforced,
			Mode: modeReport, Dest: dest, Category: "public-api", AgentID: "agent-a", AgentIDSource: "declared",
			Classifier: "not-needed", Latency: lat, Confidence: 1}
		if enforced {
			e.Applied, e.Mode = verdict, modeEnforce
		}
		if class != "" {
			e.Classes = []string{class}
			e.Rules = []finding{{rule: rule, count: 1}}
		}
		return e
	}
	return []metricEvent{
		{At: at(0), Kind: kindAgentStarted},
		{At: at(1), Kind: kindAIAppStarted, App: "ChatGPT"},
		{At: at(2), Kind: kindAISiteOpened, App: "gemini.google.com"},
		dec(3, "allow", false, "", "", "api.anthropic.com", 2*time.Millisecond),
		dec(4, "block", false, "source-code", "keyword", "api.anthropic.com", 4*time.Millisecond),
		dec(5, "block", true, "credentials", "rule:aws-access-key", "api.openai.com", 6*time.Millisecond),
		dec(6, "hold", false, "customer-data", "rule:us-ssn", "api.openai.com", 80*time.Millisecond),
		{At: at(7), Kind: kindClipboard, Bytes: 12},
		{At: at(8), Kind: kindClipboard, Bytes: 34, Rules: []finding{{rule: "credit-card", count: 1}}},
		{At: at(9), Kind: kindClipboardGuard, Bytes: 31, Mode: guardAI, Rules: []finding{{rule: "credit-card", count: 2}}},
		{At: at(10), Kind: kindIntake, App: "extension", Dest: "gemini.google.com", Bytes: 99, Rules: []finding{{rule: "email", count: 3}}},
		{At: at(11), Kind: kindIntake, App: "extension", Bytes: 5},
		{At: at(12), Kind: kindPolicyReload},
		{At: at(21), Kind: kindAIAppStopped, App: "ChatGPT"},
	}
}

func TestMetricsStoreCreatesPrivateFile(t *testing.T) {
	path := writeMetrics(t, nil)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("db mode = %v, want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
	var v int
	readOnly(t, path).QueryRow("PRAGMA user_version").Scan(&v)
	if v != metricsSchemaVersion {
		t.Errorf("user_version = %d", v)
	}
}

func TestMetricsStoreRefusesOtherSchemaAndSymlink(t *testing.T) {
	path := writeMetrics(t, nil)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("PRAGMA user_version=99")
	db.Close()
	if _, err := openMetricsStore(path, 0, 0, slog.Default()); err == nil || !strings.Contains(err.Error(), "schema version 99") {
		t.Errorf("err = %v", err)
	}
	if _, err := openMetricsDB(path, true); err == nil {
		t.Error("read-only open accepted schema version 99")
	}

	link := filepath.Join(t.TempDir(), "link.sqlite3")
	os.Symlink(path, link)
	if _, err := openMetricsDB(link, false); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlink err = %v", err)
	}
}

func TestMetricsQuery(t *testing.T) {
	path := writeMetrics(t, sampleEvents())
	f := metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}
	r, err := queryMetrics(readOnly(t, path), f, defaultStallMs, at(60))
	if err != nil {
		t.Fatal(err)
	}
	d := r.Decisions
	if d.Total != 4 || d.Blocked != 1 || d.Flagged != 2 {
		t.Errorf("total/blocked/flagged = %d/%d/%d, want 4/1/2", d.Total, d.Blocked, d.Flagged)
	}
	if d.ByVerdict["block"] != 2 || d.ByVerdict["allow"] != 1 || d.ByVerdict["hold"] != 1 {
		t.Errorf("by_verdict = %v", d.ByVerdict)
	}
	if c := d.ByClass["credentials"]; c != (classCounts{Decisions: 1, Blocked: 1}) {
		t.Errorf("credentials = %+v", c)
	}
	if c := d.ByClass["source-code"]; c != (classCounts{Decisions: 1, Flagged: 1}) {
		t.Errorf("source-code = %+v", c)
	}
	if d.ByRule["rule:aws-access-key"] != 1 || d.ByDestination["api.openai.com"] != 2 || d.ByAgent["agent-a"] != 4 {
		t.Errorf("rule/dest/agent = %v %v %v", d.ByRule, d.ByDestination, d.ByAgent)
	}
	if d.LatencyMs.Count != 4 || *d.LatencyMs.P50 != 4 || *d.LatencyMs.P95 != 80 || *d.LatencyMs.Max != 80 {
		t.Errorf("latency = %+v p50=%v p95=%v", d.LatencyMs, *d.LatencyMs.P50, *d.LatencyMs.P95)
	}
	if d.PerHour == nil || *d.PerHour != 4 {
		t.Errorf("per_hour = %v", d.PerHour)
	}

	c := r.Clipboard
	if c.Copies != 3 || c.Sensitive != 2 || c.Guarded != 1 || c.ByRule["credit-card"] != 3 {
		t.Errorf("clipboard = %+v", c)
	}
	if r.Intake.Scans != 2 || r.Intake.Flagged != 1 || r.Intake.ByRule["email"] != 3 {
		t.Errorf("intake = %+v", r.Intake)
	}
	if r.Policy.Reloads != 1 {
		t.Errorf("reloads = %d", r.Policy.Reloads)
	}

	// ChatGPT ran minutes 1 to 21; Gemini is still open at the window end.
	if u := r.AIUsage.Apps["ChatGPT"]; u != (usage{Sessions: 1, ActiveMs: 20 * 60_000}) {
		t.Errorf("ChatGPT usage = %+v", u)
	}
	if u := r.AIUsage.Sites["gemini.google.com"]; u.ActiveMs != 58*60_000 || !u.Ongoing || r.AIUsage.Ongoing != 1 {
		t.Errorf("gemini usage = %+v ongoing = %d", u, r.AIUsage.Ongoing)
	}
	if r.AIUsage.Apps["ChatGPT"].Ongoing {
		t.Error("ChatGPT stopped before the window end; should not be ongoing")
	}
	if r.Coverage.EventsInWindow != len(sampleEvents()) || r.Coverage.Incomplete {
		t.Errorf("coverage = %+v", r.Coverage)
	}
}

func TestMetricsQueryFiltersAndWindow(t *testing.T) {
	db := readOnly(t, writeMetrics(t, sampleEvents()))
	full := metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}

	f := full
	f.Class = "credentials"
	r, _ := queryMetrics(db, f, defaultStallMs, at(60))
	if r.Decisions.Total != 1 || r.Decisions.Blocked != 1 {
		t.Errorf("class filter: %+v", r.Decisions)
	}
	f = full
	f.Dest = "api.anthropic.com"
	r, _ = queryMetrics(db, f, defaultStallMs, at(60))
	if r.Decisions.Total != 2 {
		t.Errorf("dest filter total = %d", r.Decisions.Total)
	}

	// A window that clips ChatGPT's run to minutes 11 to 16.
	r, _ = queryMetrics(db, metricsFilters{FromMs: at(11).UnixMilli(), ToMs: at(16).UnixMilli()}, defaultStallMs, at(60))
	if u := r.AIUsage.Apps["ChatGPT"]; u.ActiveMs != 5*60_000 {
		t.Errorf("clipped usage = %+v", u)
	}
	if r.Decisions.Total != 0 {
		t.Errorf("decisions outside the window counted: %d", r.Decisions.Total)
	}
}

func TestMetricsUncleanStopIsCensored(t *testing.T) {
	db := readOnly(t, writeMetrics(t, []metricEvent{
		{At: at(0), Kind: kindAgentStarted},
		{At: at(1), Kind: kindAIAppStarted, App: "Cursor"},
		{At: at(5), Kind: kindClipboard, Bytes: 1}, // last sign of life before a crash
		{At: at(30), Kind: kindAgentStarted},
		{At: at(31), Kind: kindAIAppStarted, App: "Cursor"},
		{At: at(40), Kind: kindAgentStopped},
	}))
	r, err := queryMetrics(db, metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}, defaultStallMs, at(60))
	if err != nil {
		t.Fatal(err)
	}
	// 1 to 5 (censored at the last event before the restart) plus 31 to 40.
	if u := r.AIUsage.Apps["Cursor"]; u != (usage{Sessions: 2, ActiveMs: 13 * 60_000}) {
		t.Errorf("usage = %+v", u)
	}
	if r.AIUsage.Censored != 1 || r.AIUsage.Ongoing != 0 {
		t.Errorf("censored/ongoing = %d/%d", r.AIUsage.Censored, r.AIUsage.Ongoing)
	}
}

func TestMetricsRetentionPrunes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.sqlite3")
	s, err := openMetricsStore(path, time.Hour, 0, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	s.Record(metricEvent{At: time.Now().Add(-3 * time.Hour), Kind: kindDecision, Verdict: "block", Classes: []string{"old"}})
	s.Record(metricEvent{At: time.Now(), Kind: kindDecision, Verdict: "allow", Classes: []string{"new"}})
	s.Close()

	s, err = openMetricsStore(path, time.Hour, 0, slog.Default()) // prunes on open
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	db := readOnly(t, path)
	var events, labels int
	db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events)
	db.QueryRow("SELECT COUNT(*) FROM event_labels").Scan(&labels)
	if events != 1 || labels != 1 {
		t.Errorf("after prune: events=%d labels=%d, want 1 and 1 (labels cascade)", events, labels)
	}
}

func TestMetricsRecordNeverBlocks(t *testing.T) {
	s := &metricsStore{ch: make(chan metricEvent, 1)} // no writer running
	s.Record(metricEvent{Kind: kindClipboard})
	s.Record(metricEvent{Kind: kindClipboard})
	if s.dropped.Load() != 1 {
		t.Errorf("dropped = %d, want 1", s.dropped.Load())
	}

	path := writeMetrics(t, nil)
	st, _ := openMetricsStore(path, 0, 0, slog.Default())
	st.Close()
	st.Record(metricEvent{Kind: kindClipboard}) // after Close: ignored, no panic
}

func TestMetricsExport(t *testing.T) {
	path := writeMetrics(t, sampleEvents())
	var out bytes.Buffer
	n, err := exportMetrics(readOnly(t, path), metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}, &out)
	if err != nil || n != len(sampleEvents()) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	sc := bufio.NewScanner(&out)
	var prev int64
	for sc.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			t.Fatal(err)
		}
		if seq := int64(obj["seq"].(float64)); seq <= prev {
			t.Errorf("export out of order at seq %d", seq)
		} else {
			prev = seq
		}
		for _, banned := range []string{"text", "body", "prompt", "cmd"} {
			if _, ok := obj[banned]; ok {
				t.Errorf("export has a %q field", banned)
			}
		}
		if obj["kind"] == kindDecision && obj["verdict"] == "block" && obj["enforced"] == true {
			if ls, ok := obj["labels"].([]any); !ok || len(ls) != 2 {
				t.Errorf("blocked decision labels = %v", obj["labels"])
			}
		}
	}
}

func TestMetricsCLI(t *testing.T) {
	path := writeMetrics(t, sampleEvents())
	now := at(60)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runMetricsCLI(args, &out, &errb, now)
		return code, out.String(), errb.String()
	}

	code, out, _ := run("query", "--db", path, "--from", "2h")
	if code != 0 || !strings.Contains(out, "decisions total=4 blocked=1 flagged_report_only=2") ||
		!strings.Contains(out, `ai_usage.app "ChatGPT" sessions=1 active_ms=1200000`) {
		t.Errorf("query text (code %d):\n%s", code, out)
	}
	code, out, _ = run("query", "--db", path, "--from", "2h", "--json", "--class", "credentials")
	var r metricsReport
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.Decisions.Total != 1 || r.Filters["class"] != "credentials" {
		t.Errorf("query json (code %d): %s", code, out)
	}

	exportPath := filepath.Join(t.TempDir(), "out.ndjson")
	if code, _, _ = run("export", "--db", path, "--from", "2h", "--output", exportPath); code != 0 {
		t.Errorf("export code %d", code)
	}
	if fi, err := os.Stat(exportPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("export file: %v %v", fi, err)
	}

	if code, _, errs := run("clear", "--db", path); code != 2 || !strings.Contains(errs, "--yes") {
		t.Errorf("clear without --yes: code %d %s", code, errs)
	}
	if code, _, _ = run("clear", "--db", path, "--yes"); code != 0 {
		t.Errorf("clear code %d", code)
	}
	_, out, _ = run("query", "--db", path, "--from", "2h")
	if !strings.Contains(out, "decisions total=0") {
		t.Errorf("after clear:\n%s", out)
	}

	if code, _, _ = run("query", "--db", filepath.Join(t.TempDir(), "missing.sqlite3")); code != 1 {
		t.Errorf("missing db code %d", code)
	}
	if code, _, _ = run("query", "--db", path, "--from", "yesterday"); code != 2 {
		t.Errorf("bad --from code %d", code)
	}
	if code, _, _ = run("frobnicate"); code != 2 {
		t.Errorf("unknown subcommand code %d", code)
	}
}

func TestParseMetricsTime(t *testing.T) {
	now := metricsBase
	for in, want := range map[string]int64{
		"1791600000000":        1791600000000,
		"2026-10-09T11:00:00Z": now.Add(-time.Hour).UnixMilli(),
		"90m":                  now.Add(-90 * time.Minute).UnixMilli(),
		"7d":                   now.Add(-7 * 24 * time.Hour).UnixMilli(),
	} {
		if got, err := parseMetricsTime(in, now); err != nil || got != want {
			t.Errorf("%s = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseMetricsTime("-5h", now); err == nil {
		t.Error("negative duration accepted")
	}
}

func TestCapLabel(t *testing.T) {
	if got := capLabel(strings.Repeat("x", 500)); len(got) != 64 {
		t.Errorf("len = %d", len(got))
	}
}

func TestMetricsMigratesVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, at_ms INTEGER NOT NULL, kind TEXT NOT NULL,
			verdict TEXT, applied TEXT, enforced INTEGER, mode TEXT, dest TEXT, category TEXT, agent_id TEXT,
			agent_id_source TEXT, app TEXT, classifier TEXT, bytes INTEGER, latency_us INTEGER, confidence REAL)`,
		`CREATE TABLE event_labels (seq INTEGER NOT NULL REFERENCES events(seq) ON DELETE CASCADE,
			label_kind TEXT NOT NULL, value TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)`,
		`INSERT INTO meta VALUES ('dropped_events', 0)`,
		`INSERT INTO events (at_ms, kind, app) VALUES (1, 'ai_app_started', 'ChatGPT')`,
		`PRAGMA user_version=1`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := openMetricsStore(path, 0, 0, slog.Default())
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	s.Record(metricEvent{At: at(0), Kind: kindSessionStarted, SessionID: "s1", AgentKind: "claude-code"})
	s.Close()
	ro := readOnly(t, path)
	var v, n int
	ro.QueryRow("PRAGMA user_version").Scan(&v)
	ro.QueryRow("SELECT COUNT(*) FROM events WHERE session_id = 's1' OR app = 'ChatGPT'").Scan(&n)
	if v != metricsSchemaVersion || n != 2 {
		t.Errorf("after migration: version=%d rows=%d, want %d and 2 (old row kept)", v, n, metricsSchemaVersion)
	}
}

func TestTokenMetricsQuery(t *testing.T) {
	tok := func(min int, model, host string, in, out int64) metricEvent {
		return metricEvent{At: at(min), Kind: kindTokenUsage, Model: model, Provider: providerFor(host),
			Dest: host, InTokens: in, OutTokens: out}
	}
	db := readOnly(t, writeMetrics(t, []metricEvent{
		tok(1, "claude-opus-5-5", "api.anthropic.com", 1000, 200),
		tok(2, "claude-opus-5-5", "api.anthropic.com", 500, 100),
		tok(3, "gpt-5", "api.openai.com", 2000, 900),
	}))
	r, err := queryMetrics(db, metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}, defaultStallMs, at(60))
	if err != nil {
		t.Fatal(err)
	}
	tk := r.Tokens
	if tk.Requests != 3 || tk.InputTokens != 3500 || tk.OutputTokens != 1200 || tk.TotalTokens != 4700 {
		t.Errorf("tokens totals = %+v", tk)
	}
	if m := tk.ByModel["claude-opus-5-5"]; m.Input != 1500 || m.Output != 300 || m.Requests != 2 {
		t.Errorf("by_model opus = %+v", m)
	}
	if p := tk.ByProvider["openai"]; p.Input != 2000 || p.Output != 900 {
		t.Errorf("by_provider openai = %+v", p)
	}
	// Model filter.
	rf, _ := queryMetrics(db, metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli(), Model: "gpt-5"}, defaultStallMs, at(60))
	if rf.Tokens.TotalTokens != 2900 {
		t.Errorf("filtered total = %d", rf.Tokens.TotalTokens)
	}
}
