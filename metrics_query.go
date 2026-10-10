package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// agent11 metrics query|export|clear: the read side of the metrics store,
// modeled on c11's journal command. It works whether or not agent11 is
// running; query and export open the database read-only.

const metricsUsage = `Usage: agent11 metrics <query|export|clear> [options]

query   Summarize activity in a window. --json for a machine-readable report.
export  Write body-free, ordered NDJSON to stdout or --output <path>.
clear   Delete all stored metrics; requires --yes.

Options: --db <path>          (default: %s)
         --from <time> --to <time>   epoch ms, RFC 3339, or a duration back from
                                     now such as 24h or 7d (default: last 24h)
query:   --json  --class <id>  --dest <host>  --category <name>  --agent <id>
         (class, dest, category, and agent filter decisions only)
         --agent-kind <kind>  --model <id>  (agent sessions; --model also filters decisions)
         --stall-ms <ms>  working with no evidence this long is a stall (default 900000)
export:  --output <path>  (created 0600)
clear:   --yes
`

type metricsFilters struct {
	FromMs, ToMs int64
	Class        string
	Dest         string
	Category     string
	Agent        string
	AgentKind    string
	Model        string
}

// runMetricsCLI handles "agent11 metrics ..." and returns the exit code.
func runMetricsCLI(args []string, stdout, stderr io.Writer, now time.Time) int {
	usage := func() { fmt.Fprintf(stderr, metricsUsage, defaultMetricsPath()) }
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return 2
	}
	cmd := args[0]
	fset := flag.NewFlagSet("metrics "+cmd, flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = usage
	dbPath := fset.String("db", defaultMetricsPath(), "metrics database")
	from := fset.String("from", "24h", "window start")
	to := fset.String("to", "", "window end (default now)")
	asJSON := fset.Bool("json", false, "JSON output")
	class := fset.String("class", "", "decisions for this class only")
	dest := fset.String("dest", "", "decisions to this host only")
	category := fset.String("category", "", "decisions to this destination category only")
	agent := fset.String("agent", "", "decisions from this declared agent ID only")
	agentKind := fset.String("agent-kind", "", "agent sessions of this kind only, e.g. claude-code")
	model := fset.String("model", "", "this model only")
	stallMs := fset.Int64("stall-ms", defaultStallMs, "stall threshold in milliseconds")
	output := fset.String("output", "", "export file (default stdout)")
	yes := fset.Bool("yes", false, "confirm clear")
	if err := fset.Parse(args[1:]); err != nil {
		return 2
	}

	fromMs, err := parseMetricsTime(*from, now)
	if err != nil {
		fmt.Fprintln(stderr, "error: --from:", err)
		return 2
	}
	toMs := now.UnixMilli()
	if *to != "" {
		if toMs, err = parseMetricsTime(*to, now); err != nil {
			fmt.Fprintln(stderr, "error: --to:", err)
			return 2
		}
	}
	if fromMs >= toMs {
		fmt.Fprintln(stderr, "error: --from must be before --to")
		return 2
	}
	if *stallMs <= 0 {
		fmt.Fprintln(stderr, "error: --stall-ms must be positive")
		return 2
	}
	f := metricsFilters{FromMs: fromMs, ToMs: toMs, Class: *class, Dest: *dest, Category: *category, Agent: *agent,
		AgentKind: *agentKind, Model: *model}

	switch cmd {
	case "query":
		db, err := openMetricsDB(*dbPath, true)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		defer db.Close()
		r, err := queryMetrics(db, f, *stallMs, now)
		if err != nil {
			fmt.Fprintln(stderr, "error: query:", err)
			return 1
		}
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.Encode(r)
		} else {
			writeMetricsText(stdout, r)
		}
		return 0
	case "export":
		db, err := openMetricsDB(*dbPath, true)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		defer db.Close()
		w := stdout
		if *output != "" {
			file, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				return 1
			}
			defer file.Close()
			w = file
		}
		n, err := exportMetrics(db, f, w)
		if err != nil {
			fmt.Fprintln(stderr, "error: export:", err)
			return 1
		}
		if *output != "" {
			fmt.Fprintf(stderr, "exported %d events to %s\n", n, *output)
		}
		return 0
	case "clear":
		if !*yes {
			fmt.Fprintln(stderr, "error: clear deletes all stored metrics; rerun with --yes")
			return 2
		}
		if _, err := os.Lstat(*dbPath); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		db, err := openMetricsDB(*dbPath, false)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		defer db.Close()
		if err := clearMetrics(db); err != nil {
			fmt.Fprintln(stderr, "error: clear:", err)
			return 1
		}
		fmt.Fprintln(stderr, "metrics cleared")
		return 0
	default:
		usage()
		return 2
	}
}

// parseMetricsTime accepts epoch milliseconds, RFC 3339, or a duration back
// from now ("90m", "24h", "7d").
func parseMetricsTime(s string, now time.Time) (int64, error) {
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return ms, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli(), nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 {
			return now.Add(-time.Duration(n) * 24 * time.Hour).UnixMilli(), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d).UnixMilli(), nil
	}
	return 0, fmt.Errorf("%q is not epoch ms, RFC 3339, or a duration like 24h or 7d", s)
}

// metricsReport is the query result. Every field is a count, a duration, or a
// label; schema_version changes if a field changes meaning.
type metricsReport struct {
	SchemaVersion int               `json:"schema_version"`
	Units         map[string]string `json:"units"`
	Window        struct {
		FromMs int64 `json:"from_ms"`
		ToMs   int64 `json:"to_ms"`
	} `json:"window"`
	Filters   map[string]string        `json:"filters,omitempty"`
	Coverage  metricsCoverage          `json:"coverage"`
	Decisions decisionMetrics          `json:"decisions"`
	Clipboard clipboardMetrics         `json:"clipboard"`
	Intake    intakeMetrics            `json:"intake"`
	AIUsage   aiUsageMetrics           `json:"ai_usage"`
	Agents    agentMetrics             `json:"agents"`
	Launches  launchMetrics            `json:"launches"`
	Tokens    tokenMetrics             `json:"tokens"`
	Resources map[string]resourceUsage `json:"resources"`
	Policy    struct {
		Reloads int `json:"reloads"`
	} `json:"policy"`
}

type metricsCoverage struct {
	FirstEventMs   *int64  `json:"first_event_ms"`
	LastEventMs    *int64  `json:"last_event_ms"`
	CoveredFromMs  *int64  `json:"covered_from_ms"`
	CoveredHours   float64 `json:"covered_hours"`
	EventsInWindow int     `json:"events_in_window"`
	DroppedEvents  int64   `json:"dropped_events"`
	Incomplete     bool    `json:"incomplete"` // the window starts before the oldest retained event
}

type classCounts struct {
	Decisions int `json:"decisions"`
	Blocked   int `json:"blocked"`
	Flagged   int `json:"flagged_report_only"`
}

type decisionMetrics struct {
	Total         int                    `json:"total"`
	Blocked       int                    `json:"blocked"`
	Flagged       int                    `json:"flagged_report_only"` // verdict not allow, not enforced
	PerHour       *float64               `json:"per_hour"`
	ByVerdict     map[string]int         `json:"by_verdict"`
	ByCategory    map[string]int         `json:"by_category"`
	ByDestination map[string]int         `json:"by_destination"`
	ByAgent       map[string]int         `json:"by_agent"`
	ByClass       map[string]classCounts `json:"by_class"`
	ByRule        map[string]int         `json:"by_rule"`
	Classifier    map[string]int         `json:"classifier"`
	LatencyMs     latencySummary         `json:"latency_ms"`
}

type latencySummary struct {
	Count int      `json:"count"`
	P50   *float64 `json:"p50"`
	P95   *float64 `json:"p95"`
	P99   *float64 `json:"p99"`
	Max   *float64 `json:"max"`
}

type clipboardMetrics struct {
	Copies    int            `json:"copies"`
	Sensitive int            `json:"sensitive"`
	Guarded   int            `json:"guarded"`
	ByRule    map[string]int `json:"by_rule"`
}

type intakeMetrics struct {
	Scans   int            `json:"scans"`
	Flagged int            `json:"flagged"`
	ByRule  map[string]int `json:"by_rule"`
}

type usage struct {
	Sessions int   `json:"sessions"`
	ActiveMs int64 `json:"active_ms"`
	Ongoing  bool  `json:"ongoing"` // still running at the window end
}

type aiUsageMetrics struct {
	Apps     map[string]usage `json:"apps"`
	Sites    map[string]usage `json:"sites"`
	Censored int              `json:"censored"` // intervals cut short by an unclean stop
	Ongoing  int              `json:"ongoing"`  // intervals still open at the window end
}

func queryMetrics(db *sql.DB, f metricsFilters, stallMs int64, now time.Time) (*metricsReport, error) {
	r := &metricsReport{SchemaVersion: metricsSchemaVersion,
		Units: map[string]string{"duration": "ms", "latency": "ms (decision time inside agent11)",
			"rate": "per covered hour", "window": "[from,to)"}}
	r.Window.FromMs, r.Window.ToMs = f.FromMs, f.ToMs
	r.Filters = map[string]string{}
	for k, v := range map[string]string{"class": f.Class, "dest": f.Dest, "category": f.Category, "agent": f.Agent,
		"agent_kind": f.AgentKind, "model": f.Model} {
		if v != "" {
			r.Filters[k] = v
		}
	}

	// Coverage: what the store actually holds for this window.
	var first, last sql.NullInt64
	if err := db.QueryRow(`SELECT MIN(at_ms), MAX(at_ms) FROM events`).Scan(&first, &last); err != nil {
		return nil, err
	}
	if first.Valid {
		r.Coverage.FirstEventMs, r.Coverage.LastEventMs = &first.Int64, &last.Int64
		from := max(f.FromMs, first.Int64)
		r.Coverage.CoveredFromMs = &from
		r.Coverage.Incomplete = f.FromMs < first.Int64
		if to := min(f.ToMs, now.UnixMilli()); to > from {
			r.Coverage.CoveredHours = round2(float64(to-from) / float64(time.Hour.Milliseconds()))
		}
	}
	db.QueryRow(`SELECT value FROM meta WHERE key = 'dropped_events'`).Scan(&r.Coverage.DroppedEvents)
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE at_ms >= ? AND at_ms < ?`, f.FromMs, f.ToMs).
		Scan(&r.Coverage.EventsInWindow); err != nil {
		return nil, err
	}

	if err := queryDecisions(db, f, r); err != nil {
		return nil, fmt.Errorf("decisions: %w", err)
	}
	if err := queryClipboardAndIntake(db, f, r); err != nil {
		return nil, fmt.Errorf("clipboard: %w", err)
	}
	if err := queryAIUsage(db, f, now, r); err != nil {
		return nil, fmt.Errorf("ai usage: %w", err)
	}
	if err := queryAgents(db, f, stallMs, now, r); err != nil {
		return nil, fmt.Errorf("agents: %w", err)
	}
	if err := queryLaunches(db, f, r); err != nil {
		return nil, fmt.Errorf("launches: %w", err)
	}
	if err := queryTokens(db, f, r); err != nil {
		return nil, fmt.Errorf("tokens: %w", err)
	}
	if err := queryResources(db, f, r); err != nil {
		return nil, fmt.Errorf("resources: %w", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = ? AND at_ms >= ? AND at_ms < ?`,
		kindPolicyReload, f.FromMs, f.ToMs).Scan(&r.Policy.Reloads); err != nil {
		return nil, err
	}
	return r, nil
}

// decisionWhere builds the filter clause for decision rows aliased as e.
func decisionWhere(f metricsFilters) (string, []any) {
	where := []string{"e.kind = 'decision'", "e.at_ms >= ?", "e.at_ms < ?"}
	args := []any{f.FromMs, f.ToMs}
	if f.Dest != "" {
		where, args = append(where, "e.dest = ?"), append(args, f.Dest)
	}
	if f.Category != "" {
		where, args = append(where, "e.category = ?"), append(args, f.Category)
	}
	if f.Agent != "" {
		where, args = append(where, "e.agent_id = ?"), append(args, f.Agent)
	}
	if f.Model != "" {
		where, args = append(where, "e.model = ?"), append(args, f.Model)
	}
	if f.Class != "" {
		where = append(where, "EXISTS (SELECT 1 FROM event_labels c WHERE c.seq = e.seq AND c.label_kind = 'class' AND c.value = ?)")
		args = append(args, f.Class)
	}
	return strings.Join(where, " AND "), args
}

func queryDecisions(db *sql.DB, f metricsFilters, r *metricsReport) error {
	d := &r.Decisions
	d.ByVerdict, d.ByCategory, d.ByDestination, d.ByAgent = map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	d.ByClass, d.ByRule, d.Classifier = map[string]classCounts{}, map[string]int{}, map[string]int{}
	where, args := decisionWhere(f)

	flaggedExpr := `SUM(CASE WHEN e.verdict != 'allow' AND e.enforced = 0 THEN 1 ELSE 0 END)`
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(e.enforced), 0), COALESCE(`+flaggedExpr+`, 0)
		FROM events e WHERE `+where, args...).Scan(&d.Total, &d.Blocked, &d.Flagged); err != nil {
		return err
	}
	if r.Coverage.CoveredHours > 0 {
		v := round2(float64(d.Total) / r.Coverage.CoveredHours)
		d.PerHour = &v
	}
	groups := []struct {
		col string
		out map[string]int
	}{{"e.verdict", d.ByVerdict}, {"e.category", d.ByCategory}, {"e.dest", d.ByDestination},
		{"COALESCE(e.agent_id, '(none)')", d.ByAgent}, {"e.classifier", d.Classifier}}
	for _, g := range groups {
		if err := groupCount(db, `SELECT `+g.col+`, COUNT(*) FROM events e WHERE `+where+` GROUP BY 1`, args, g.out); err != nil {
			return err
		}
	}
	rows, err := db.Query(`SELECT l.value, COUNT(*), COALESCE(SUM(e.enforced), 0), COALESCE(`+flaggedExpr+`, 0)
		FROM event_labels l JOIN events e ON e.seq = l.seq
		WHERE l.label_kind = 'class' AND `+where+` GROUP BY l.value`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var c classCounts
		if err := rows.Scan(&id, &c.Decisions, &c.Blocked, &c.Flagged); err != nil {
			rows.Close()
			return err
		}
		d.ByClass[id] = c
	}
	rows.Close()
	if err := groupCount(db, `SELECT l.value, SUM(l.count) FROM event_labels l JOIN events e ON e.seq = l.seq
		WHERE l.label_kind = 'rule' AND `+where+` GROUP BY l.value`, args, d.ByRule); err != nil {
		return err
	}

	// Latency percentiles, nearest rank, read in order from the index-free
	// column; a local store holds at most weeks of decisions.
	lrows, err := db.Query(`SELECT e.latency_us FROM events e WHERE `+where+` AND e.latency_us IS NOT NULL ORDER BY e.latency_us`, args...)
	if err != nil {
		return err
	}
	var lat []int64
	for lrows.Next() {
		var us int64
		if err := lrows.Scan(&us); err != nil {
			lrows.Close()
			return err
		}
		lat = append(lat, us)
	}
	lrows.Close()
	d.LatencyMs.Count = len(lat)
	if len(lat) > 0 {
		pick := func(p int) *float64 {
			i := max((len(lat)*p+99)/100-1, 0)
			v := round2(float64(lat[i]) / 1000)
			return &v
		}
		d.LatencyMs.P50, d.LatencyMs.P95, d.LatencyMs.P99 = pick(50), pick(95), pick(99)
		mx := round2(float64(lat[len(lat)-1]) / 1000)
		d.LatencyMs.Max = &mx
	}
	return nil
}

func queryClipboardAndIntake(db *sql.DB, f metricsFilters, r *metricsReport) error {
	c, in := &r.Clipboard, &r.Intake
	c.ByRule, in.ByRule = map[string]int{}, map[string]int{}
	hasRule := `EXISTS (SELECT 1 FROM event_labels l WHERE l.seq = e.seq AND l.label_kind = 'rule')`
	win := []any{f.FromMs, f.ToMs}
	q := func(kind string, total, flagged *int) error {
		return db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN `+hasRule+` THEN 1 ELSE 0 END), 0)
			FROM events e WHERE e.kind = ? AND e.at_ms >= ? AND e.at_ms < ?`, kind, f.FromMs, f.ToMs).Scan(total, flagged)
	}
	var guardedSensitive int
	if err := q(kindClipboard, &c.Copies, &c.Sensitive); err != nil {
		return err
	}
	if err := q(kindClipboardGuard, &c.Guarded, &guardedSensitive); err != nil {
		return err
	}
	// A guarded copy is a copy too, and always a sensitive one.
	c.Copies += c.Guarded
	c.Sensitive += c.Guarded
	if err := q(kindIntake, &in.Scans, &in.Flagged); err != nil {
		return err
	}
	ruleSQL := `SELECT l.value, SUM(l.count) FROM event_labels l JOIN events e ON e.seq = l.seq
		WHERE l.label_kind = 'rule' AND e.kind IN (%s) AND e.at_ms >= ? AND e.at_ms < ? GROUP BY l.value`
	if err := groupCount(db, fmt.Sprintf(ruleSQL, "'clipboard','clipboard_guarded'"), win, c.ByRule); err != nil {
		return err
	}
	return groupCount(db, fmt.Sprintf(ruleSQL, "'intake'"), win, in.ByRule)
}

// queryAIUsage rebuilds open intervals for AI apps and sites from their
// start and stop events, then sums each interval's overlap with the window.
// An interval left open by an unclean stop ends at the last event recorded
// before the next start, and is counted as censored.
func queryAIUsage(db *sql.DB, f metricsFilters, now time.Time, r *metricsReport) error {
	u := &r.AIUsage
	u.Apps, u.Sites = map[string]usage{}, map[string]usage{}
	rows, err := db.Query(`SELECT at_ms, kind, COALESCE(app, '') FROM events WHERE at_ms < ? ORDER BY seq`, f.ToMs)
	if err != nil {
		return err
	}
	defer rows.Close()

	type open struct {
		name  string
		start int64
		site  bool
	}
	opened := map[string]open{}
	var lastAt int64
	closeOne := func(o open, end int64) {
		name := o.name
		target := u.Apps
		if o.site {
			target = u.Sites
		}
		if overlap := min(end, f.ToMs) - max(o.start, f.FromMs); overlap > 0 || (o.start >= f.FromMs && o.start < f.ToMs) {
			s := target[name]
			s.Sessions++
			s.ActiveMs += max(overlap, 0)
			target[name] = s
		}
	}
	closeAll := func(end int64, censored bool) {
		for _, o := range opened {
			closeOne(o, end)
			if censored {
				u.Censored++
			}
		}
		clear(opened)
	}
	for rows.Next() {
		var at int64
		var kind, app string
		if err := rows.Scan(&at, &kind, &app); err != nil {
			return err
		}
		switch kind {
		case kindAgentStarted:
			closeAll(lastAt, true) // a start with intervals still open means the last run never stopped cleanly
		case kindAgentStopped:
			closeAll(at, false)
		case kindAIAppStarted, kindAISiteOpened:
			key := keyFor(kind, app)
			if _, ok := opened[key]; !ok {
				opened[key] = open{name: app, start: at, site: kind == kindAISiteOpened}
			}
		case kindAIAppStopped, kindAISiteClosed:
			key := keyFor(kind, app)
			if o, ok := opened[key]; ok {
				closeOne(o, at)
				delete(opened, key)
			}
		}
		lastAt = at
	}
	if err := rows.Err(); err != nil {
		return err
	}
	end := min(f.ToMs, now.UnixMilli())
	u.Ongoing = len(opened)
	for _, o := range opened {
		closeOne(o, end)
		target := u.Apps
		if o.site {
			target = u.Sites
		}
		if s, ok := target[o.name]; ok {
			s.Ongoing = true
			target[o.name] = s
		}
	}
	return nil
}

// keyFor keeps an app and a site with the same name apart.
func keyFor(kind, name string) string {
	if kind == kindAISiteOpened || kind == kindAISiteClosed {
		return "site\x00" + name
	}
	return "app\x00" + name
}

func groupCount(db *sql.DB, q string, args []any, out map[string]int) error {
	rows, err := db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k sql.NullString
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		key := k.String
		if !k.Valid {
			key = "(none)"
		}
		out[key] += n
	}
	return rows.Err()
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// writeMetricsText prints the report as key=value lines, one topic per line.
func writeMetricsText(w io.Writer, r *metricsReport) {
	kv := func(m map[string]int) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s=%d", k, m[k])
		}
		return strings.Join(parts, " ")
	}
	opt := func(v *float64) string {
		if v == nil {
			return "null"
		}
		return strconv.FormatFloat(*v, 'f', -1, 64)
	}
	ms := func(t int64) string { return time.UnixMilli(t).Format(time.RFC3339) }
	fmt.Fprintf(w, "window %s to %s covered_hours=%v events=%d dropped=%d incomplete=%v\n",
		ms(r.Window.FromMs), ms(r.Window.ToMs), r.Coverage.CoveredHours, r.Coverage.EventsInWindow,
		r.Coverage.DroppedEvents, r.Coverage.Incomplete)
	if len(r.Filters) > 0 {
		fmt.Fprintf(w, "filters %s\n", kvStr(r.Filters))
	}
	d := r.Decisions
	fmt.Fprintf(w, "decisions total=%d blocked=%d flagged_report_only=%d per_hour=%s\n", d.Total, d.Blocked, d.Flagged, opt(d.PerHour))
	fmt.Fprintf(w, "decisions.verdict %s\n", kv(d.ByVerdict))
	fmt.Fprintf(w, "decisions.category %s\n", kv(d.ByCategory))
	fmt.Fprintf(w, "decisions.destination %s\n", kv(d.ByDestination))
	fmt.Fprintf(w, "decisions.agent %s\n", kv(d.ByAgent))
	classIDs := make([]string, 0, len(d.ByClass))
	for id := range d.ByClass {
		classIDs = append(classIDs, id)
	}
	slices.Sort(classIDs)
	for _, id := range classIDs {
		c := d.ByClass[id]
		fmt.Fprintf(w, "decisions.class %s decisions=%d blocked=%d flagged_report_only=%d\n", id, c.Decisions, c.Blocked, c.Flagged)
	}
	fmt.Fprintf(w, "decisions.rule %s\n", kv(d.ByRule))
	fmt.Fprintf(w, "decisions.classifier %s\n", kv(d.Classifier))
	fmt.Fprintf(w, "decisions.latency_ms count=%d p50=%s p95=%s p99=%s max=%s\n", d.LatencyMs.Count,
		opt(d.LatencyMs.P50), opt(d.LatencyMs.P95), opt(d.LatencyMs.P99), opt(d.LatencyMs.Max))
	tk := r.Tokens
	fmt.Fprintf(w, "tokens requests=%d input=%d output=%d total=%d\n", tk.Requests, tk.InputTokens, tk.OutputTokens, tk.TotalTokens)
	for _, model := range sortedKeys(tk.ByModel) {
		p := tk.ByModel[model]
		fmt.Fprintf(w, "tokens.model %s input=%d output=%d requests=%d\n", model, p.Input, p.Output, p.Requests)
	}
	c := r.Clipboard
	fmt.Fprintf(w, "clipboard copies=%d sensitive=%d guarded=%d rules: %s\n", c.Copies, c.Sensitive, c.Guarded, kv(c.ByRule))
	fmt.Fprintf(w, "intake scans=%d flagged=%d rules: %s\n", r.Intake.Scans, r.Intake.Flagged, kv(r.Intake.ByRule))
	writeUsage := func(label string, m map[string]usage) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		slices.SortFunc(names, func(a, b string) int { return int(m[b].ActiveMs - m[a].ActiveMs) })
		for _, n := range names {
			fmt.Fprintf(w, "ai_usage.%s %q sessions=%d active_ms=%d\n", label, n, m[n].Sessions, m[n].ActiveMs)
		}
	}
	writeUsage("app", r.AIUsage.Apps)
	writeUsage("site", r.AIUsage.Sites)
	fmt.Fprintf(w, "ai_usage censored=%d ongoing=%d\n", r.AIUsage.Censored, r.AIUsage.Ongoing)
	writeAgentsText(w, r, kv, opt)
	fmt.Fprintf(w, "policy reloads=%d\n", r.Policy.Reloads)
}

func writeAgentsText(w io.Writer, r *metricsReport, kv func(map[string]int) string, opt func(*float64) string) {
	a := r.Agents
	kv64 := func(m map[string]int64, keys ...string) string {
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s=%d", k, m[k])
		}
		return strings.Join(parts, " ")
	}
	optI := func(v *int64) string {
		if v == nil {
			return "null"
		}
		return strconv.FormatInt(*v, 10)
	}
	fmt.Fprintf(w, "agents.sessions started=%d seen=%d kinds: %s models: %s\n", a.Sessions.Started, a.Sessions.Seen,
		kv(a.Sessions.ByAgentKind), kv(a.Sessions.ByModel))
	fmt.Fprintf(w, "agents.time_in_state_ms %s\n", kv64(a.TimeInStateMs, "working", "blocked", "idle", "error", "unknown"))
	fmt.Fprintf(w, "agents.blocked_ms %s\n", kv64(a.BlockedMs, "approval", "question", "plan_review"))
	fmt.Fprintf(w, "agents.turns started=%d completed=%d ambiguous=%d per_hour=%s\n", a.Turns.Started, a.Turns.Completed,
		a.Turns.Ambiguous, opt(a.Turns.PerHour))
	o := a.OperatorResponse
	fmt.Fprintf(w, "agents.operator_response status=%s wait_count=%d wait_ms=%d wait_avg_ms=%s wait_p50_ms=%s wait_p95_ms=%s censored=%d resume_ms=null by_reason: %s\n",
		o.Status, o.WaitCount, o.WaitMs, opt(o.WaitAvgMs), optI(o.WaitP50Ms), optI(o.WaitP95Ms), o.Censored, kv(o.ByReason))
	fmt.Fprintf(w, "agents.errors session_failure=%d child_spawned=%d child_completed=%d censored_intervals=%d\n",
		a.Errors.SessionFailure, a.Errors.ChildSpawned, a.Errors.ChildCompleted, a.Censored)
	for _, s := range a.Stalls {
		fmt.Fprintf(w, "agents.stall session=%s start=%s duration_ms=%d threshold_ms=%d ongoing=%v\n", s.SessionID,
			time.UnixMilli(s.StartMs).Format(time.RFC3339), s.DurationMs, s.ThresholdMs, s.Ongoing)
	}
	l := r.Launches
	fmt.Fprintf(w, "launches app_starts: %s\n", kv(l.AppStarts))
	fmt.Fprintf(w, "launches requests_by_model: %s\n", kv(l.RequestsByModel))
	fmt.Fprintf(w, "launches requests_by_provider: %s\n", kv(l.RequestsByProvider))
	apps := make([]string, 0, len(r.Resources))
	for app := range r.Resources {
		apps = append(apps, app)
	}
	slices.Sort(apps)
	for _, app := range apps {
		u := r.Resources[app]
		fmt.Fprintf(w, "resources %q samples=%d cpu_avg_pct=%v cpu_peak_pct=%v rss_avg_mb=%v rss_peak_mb=%v procs_peak=%d\n",
			app, u.Samples, u.CPUAvg, u.CPUPeak, u.RSSAvgMB, u.RSSPeakMB, u.ProcsPeak)
	}
}

func kvStr(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, " ")
}

// exportMetrics writes one JSON object per event in the window, in order,
// with its classes and rules. Rows hold no content, so neither does this.
func exportMetrics(db *sql.DB, f metricsFilters, w io.Writer) (int, error) {
	rows, err := db.Query(`SELECT e.seq, e.at_ms, e.kind, e.verdict, e.applied, e.enforced, e.mode, e.dest, e.category,
		e.agent_id, e.agent_id_source, e.app, e.classifier, e.bytes, e.latency_us, e.confidence,
		(SELECT json_group_array(json_object('kind', l.label_kind, 'value', l.value, 'count', l.count))
		   FROM event_labels l WHERE l.seq = e.seq)
		FROM events e WHERE e.at_ms >= ? AND e.at_ms < ? ORDER BY e.seq`, f.FromMs, f.ToMs)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	n := 0
	for rows.Next() {
		var seq, at int64
		var kind string
		var verdict, applied, mode, dest, category, agentID, agentSrc, app, clf sql.NullString
		var enforced, bytes, latency sql.NullInt64
		var confidence sql.NullFloat64
		var labels string
		if err := rows.Scan(&seq, &at, &kind, &verdict, &applied, &enforced, &mode, &dest, &category,
			&agentID, &agentSrc, &app, &clf, &bytes, &latency, &confidence, &labels); err != nil {
			return n, err
		}
		obj := map[string]any{"schema_version": metricsSchemaVersion, "seq": seq, "at_ms": at, "kind": kind}
		for k, v := range map[string]sql.NullString{"verdict": verdict, "applied": applied, "mode": mode, "dest": dest,
			"category": category, "agent_id": agentID, "agent_id_source": agentSrc, "app": app, "classifier": clf} {
			if v.Valid {
				obj[k] = v.String
			}
		}
		if enforced.Valid {
			obj["enforced"] = enforced.Int64 == 1
		}
		if bytes.Valid {
			obj["bytes"] = bytes.Int64
		}
		if latency.Valid {
			obj["latency_us"] = latency.Int64
		}
		if confidence.Valid {
			obj["confidence"] = confidence.Float64
		}
		var ls []map[string]any
		if err := json.Unmarshal([]byte(labels), &ls); err == nil && len(ls) > 0 {
			obj["labels"] = ls
		}
		if err := enc.Encode(obj); err != nil {
			return n, err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	return n, bw.Flush()
}

func clearMetrics(db *sql.DB) error {
	for _, stmt := range []string{`DELETE FROM event_labels`, `DELETE FROM events`,
		`UPDATE meta SET value = 0 WHERE key = 'dropped_events'`, `VACUUM`} {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// tokenPair is input/output token totals with a request count.
type tokenPair struct {
	Requests int   `json:"requests"`
	Input    int64 `json:"input"`
	Output   int64 `json:"output"`
}

// tokenMetrics is LLM token consumption seen by the proxy. It covers only
// requests routed through agent11; other channels have no token data.
type tokenMetrics struct {
	Requests     int                  `json:"requests"`
	InputTokens  int64                `json:"input_tokens"`
	OutputTokens int64                `json:"output_tokens"`
	TotalTokens  int64                `json:"total_tokens"`
	ByModel      map[string]tokenPair `json:"by_model"`
	ByProvider   map[string]tokenPair `json:"by_provider"`
}

func queryTokens(db *sql.DB, f metricsFilters, r *metricsReport) error {
	t := &r.Tokens
	t.ByModel, t.ByProvider = map[string]tokenPair{}, map[string]tokenPair{}
	where := []string{"kind = ?", "at_ms >= ?", "at_ms < ?"}
	args := []any{kindTokenUsage, f.FromMs, f.ToMs}
	if f.Model != "" {
		where, args = append(where, "model = ?"), append(args, f.Model)
	}
	if f.Dest != "" {
		where, args = append(where, "dest = ?"), append(args, f.Dest)
	}
	if f.Agent != "" {
		where, args = append(where, "agent_id = ?"), append(args, f.Agent)
	}
	rows, err := db.Query(`SELECT COALESCE(model, '(none)'), COALESCE(provider, '(none)'), COUNT(*),
		COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0)
		FROM events WHERE `+strings.Join(where, " AND ")+` GROUP BY model, provider`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var model, provider string
		var count int
		var in, out int64
		if err := rows.Scan(&model, &provider, &count, &in, &out); err != nil {
			return err
		}
		t.Requests += count
		t.InputTokens += in
		t.OutputTokens += out
		m := t.ByModel[model]
		m.Requests += count
		m.Input += in
		m.Output += out
		t.ByModel[model] = m
		p := t.ByProvider[provider]
		p.Requests += count
		p.Input += in
		p.Output += out
		t.ByProvider[provider] = p
	}
	t.TotalTokens = t.InputTokens + t.OutputTokens
	return rows.Err()
}
