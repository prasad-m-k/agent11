package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// The dashboard is a local, read-only web view of the metrics database. It
// serves a self-contained HTML page plus a small JSON API, binds to loopback
// only, and opens the database read-only. It shows what agent11 recorded:
// AI tool usage, agent activity, and data-protection decisions. It never
// shows content, because the store holds none.

// timelinePoint is one bucket of the activity-over-time chart.
type timelinePoint struct {
	TMs       int64 `json:"t_ms"`
	Events    int   `json:"events"`
	Decisions int   `json:"decisions"`
	Blocked   int   `json:"blocked"`
	Sensitive int   `json:"sensitive"` // clipboard, guard, or intake events with a DLP rule
	Turns     int   `json:"turns"`
}

type timeline struct {
	FromMs   int64           `json:"from_ms"`
	ToMs     int64           `json:"to_ms"`
	BucketMs int64           `json:"bucket_ms"`
	Points   []timelinePoint `json:"points"`
}

// queryTimeline buckets events across the window into roughly `buckets` points.
func queryTimeline(db *sql.DB, f metricsFilters, buckets int, now time.Time) (*timeline, error) {
	to := min(f.ToMs, now.UnixMilli())
	if to <= f.FromMs {
		to = f.ToMs
	}
	if buckets < 1 {
		buckets = 1
	}
	size := max(1, (to-f.FromMs)/int64(buckets))
	n := int((to-f.FromMs+size-1)/size) + 1
	tl := &timeline{FromMs: f.FromMs, ToMs: to, BucketMs: size, Points: make([]timelinePoint, n)}
	for i := range tl.Points {
		tl.Points[i].TMs = f.FromMs + int64(i)*size
	}
	rows, err := db.Query(`SELECT (at_ms - ?) / ?, kind, COUNT(*), COALESCE(SUM(enforced), 0)
		FROM events WHERE at_ms >= ? AND at_ms < ? GROUP BY 1, 2`, f.FromMs, size, f.FromMs, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b int64
		var kind string
		var count, blocked int
		if err := rows.Scan(&b, &kind, &count, &blocked); err != nil {
			return nil, err
		}
		i := int(b)
		if i < 0 || i >= n {
			continue
		}
		p := &tl.Points[i]
		p.Events += count
		switch kind {
		case kindDecision:
			p.Decisions += count
			p.Blocked += blocked
		case kindTurnStarted:
			p.Turns += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	srows, err := db.Query(`SELECT (e.at_ms - ?) / ?, COUNT(DISTINCT e.seq) FROM events e
		JOIN event_labels l ON l.seq = e.seq
		WHERE e.kind IN ('clipboard', 'clipboard_guarded', 'intake') AND l.label_kind = 'rule'
		AND e.at_ms >= ? AND e.at_ms < ? GROUP BY 1`, f.FromMs, size, f.FromMs, to)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var b int64
		var count int
		if err := srows.Scan(&b, &count); err != nil {
			return nil, err
		}
		if i := int(b); i >= 0 && i < n {
			tl.Points[i].Sensitive += count
		}
	}
	return tl, srows.Err()
}

type dashboardServer struct {
	db      *sql.DB
	logger  *slog.Logger
	stallMs int64
}

func (s *dashboardServer) filters(r *http.Request, now time.Time) (metricsFilters, error) {
	q := r.URL.Query()
	from := q.Get("from")
	if from == "" {
		from = "24h"
	}
	fromMs, err := parseMetricsTime(from, now)
	if err != nil {
		return metricsFilters{}, fmt.Errorf("from: %w", err)
	}
	toMs := now.UnixMilli()
	if to := q.Get("to"); to != "" {
		if toMs, err = parseMetricsTime(to, now); err != nil {
			return metricsFilters{}, fmt.Errorf("to: %w", err)
		}
	}
	if fromMs >= toMs {
		return metricsFilters{}, errors.New("from must be before to")
	}
	return metricsFilters{FromMs: fromMs, ToMs: toMs, Agent: q.Get("agent"), AgentKind: q.Get("agent_kind"),
		Model: q.Get("model"), Category: q.Get("category")}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *dashboardServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		f, err := s.filters(r, time.Now())
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		rep, err := queryMetrics(s.db, f, s.stallMs, time.Now())
		if err != nil {
			s.logger.Error("dashboard metrics query failed", "err", err)
			httpError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		f, err := s.filters(r, time.Now())
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		limit, offset := 100, 0
		if n := r.URL.Query().Get("limit"); n != "" {
			fmt.Sscanf(n, "%d", &limit)
		}
		if limit < 1 || limit > 500 {
			limit = 100
		}
		if n := r.URL.Query().Get("offset"); n != "" {
			fmt.Sscanf(n, "%d", &offset)
		}
		if offset < 0 {
			offset = 0
		}
		page, err := queryEvents(s.db, f, r.URL.Query().Get("kind"), limit, offset)
		if err != nil {
			s.logger.Error("dashboard events query failed", "err", err)
			httpError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, page)
	})
	mux.HandleFunc("/api/timeline", func(w http.ResponseWriter, r *http.Request) {
		f, err := s.filters(r, time.Now())
		if err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		buckets := 48
		if n := r.URL.Query().Get("buckets"); n != "" {
			fmt.Sscanf(n, "%d", &buckets)
		}
		if buckets < 1 || buckets > 500 {
			buckets = 48
		}
		tl, err := queryTimeline(s.db, f, buckets, time.Now())
		if err != nil {
			s.logger.Error("dashboard timeline query failed", "err", err)
			httpError(w, http.StatusInternalServerError, "query failed")
			return
		}
		writeJSON(w, tl)
	})
	return mux
}

// startDashboard serves the dashboard until ctx is cancelled.
func startDashboard(ctx context.Context, addr, dbPath string, stallMs int64, logger *slog.Logger) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("dashboard address %q: %w", addr, err)
	}
	if !isLoopback(host) {
		return fmt.Errorf("refusing to bind non-loopback address %q; use 127.0.0.1 or [::1]", addr)
	}
	// A missing database is the common first run (the collector has not run
	// yet). Create an empty one so the dashboard still opens, showing zeros,
	// rather than erroring.
	if _, statErr := os.Lstat(dbPath); errors.Is(statErr, fs.ErrNotExist) {
		seed, err := openMetricsDB(dbPath, false)
		if err != nil {
			return err
		}
		if err := initMetricsSchema(seed, 0); err != nil {
			seed.Close()
			return err
		}
		seed.Close()
		logger.Info("metrics database did not exist; created an empty one", "db", dbPath)
		fmt.Fprintln(os.Stderr, "agent11 dashboard: the metrics database was empty. Run the collector ( agent11 ) to populate it.")
	}
	db, err := openMetricsDB(dbPath, true)
	if err != nil {
		return err
	}
	defer db.Close()
	srv := &http.Server{Addr: addr, Handler: (&dashboardServer{db: db, logger: logger, stallMs: stallMs}).handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	logger.Info("dashboard listening", "addr", addr, "db", dbPath)
	fmt.Fprintf(os.Stderr, "agent11 dashboard: http://%s\n", addr)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// runDashboardCLI handles "agent11 dashboard": serve the web view until
// interrupted. It needs no running agent11; it reads the database read-only.
func runDashboardCLI(args []string, stderr *os.File) int {
	fset := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dbPath := fset.String("db", defaultMetricsPath(), "metrics database")
	listen := fset.String("listen", "127.0.0.1:9090", "loopback address to serve on")
	stallMs := fset.Int64("stall-ms", defaultStallMs, "stall threshold for agent metrics, in milliseconds")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	if err := startDashboard(ctx, *listen, *dbPath, *stallMs, logger); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// eventRow is one stored event for the dashboard's timestamped list. It carries
// a precomputed, content-free detail string so the page stays small.
type eventRow struct {
	Seq    int64  `json:"seq"`
	TMs    int64  `json:"t_ms"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type eventsPage struct {
	Events []eventRow `json:"events"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

// queryEvents returns stored events in a window, newest first, paginated. An
// optional kind narrows the list. It reads the same body-free rows the store
// holds and never exposes content.
func queryEvents(db *sql.DB, f metricsFilters, kind string, limit, offset int) (*eventsPage, error) {
	where := []string{"at_ms >= ?", "at_ms < ?"}
	args := []any{f.FromMs, f.ToMs}
	if kind != "" {
		where, args = append(where, "kind = ?"), append(args, kind)
	}
	clause := strings.Join(where, " AND ")
	p := &eventsPage{Events: []eventRow{}, Limit: limit, Offset: offset}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE `+clause, args...).Scan(&p.Total); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT seq, at_ms, kind, COALESCE(verdict,''), COALESCE(applied,''), COALESCE(enforced,0),
		COALESCE(dest,''), COALESCE(app,''), COALESCE(model,''), COALESCE(agent_kind,''), COALESCE(agent_id,''),
		COALESCE(tool_class,''), COALESCE(bytes,0), COALESCE(input_tokens,0), COALESCE(output_tokens,0),
		COALESCE(cpu_max,0), COALESCE(rss_kb,0),
		COALESCE((SELECT group_concat(l.label_kind || ':' || l.value) FROM event_labels l WHERE l.seq = events.seq), '')
		FROM events WHERE `+clause+` ORDER BY seq DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r eventRow
		var verdict, applied, dest, app, model, agentKind, agentID, toolClass, labels string
		var enforced, bytes, inTok, outTok, rssKB int64
		var cpuMax float64
		if err := rows.Scan(&r.Seq, &r.TMs, &r.Kind, &verdict, &applied, &enforced, &dest, &app, &model,
			&agentKind, &agentID, &toolClass, &bytes, &inTok, &outTok, &cpuMax, &rssKB, &labels); err != nil {
			return nil, err
		}
		r.Detail = eventDetail(r.Kind, detailFields{verdict, applied, enforced == 1, dest, app, model,
			agentKind, agentID, toolClass, bytes, inTok, outTok, cpuMax, rssKB, labels})
		p.Events = append(p.Events, r)
	}
	return p, rows.Err()
}

type detailFields struct {
	verdict, applied     string
	enforced             bool
	dest, app, model     string
	agentKind, agentID   string
	toolClass            string
	bytes, inTok, outTok int64
	cpuMax               float64
	rssKB                int64
	labels               string
}

// eventDetail builds the one-line, content-free summary shown per event.
func eventDetail(kind string, d detailFields) string {
	join := func(parts ...string) string {
		var out []string
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return strings.Join(out, "  ")
	}
	var labs []string
	for _, l := range strings.Split(d.labels, ",") {
		if v := strings.TrimPrefix(l, "rule:"); v != l {
			labs = append(labs, v)
		} else if v := strings.TrimPrefix(l, "class:"); v != l {
			labs = append(labs, "["+v+"]")
		}
	}
	labels := strings.Join(labs, " ")
	switch kind {
	case kindDecision:
		v := d.verdict
		if d.enforced {
			v += " (enforced)"
		} else if d.verdict != "allow" {
			v += " (report)"
		}
		return join(v, d.dest, d.model, labels)
	case kindTokenUsage:
		return join(d.model, d.dest, fmt.Sprintf("%d in / %d out tokens", d.inTok, d.outTok))
	case kindClipboard, kindClipboardGuard, kindIntake:
		return join(fmt.Sprintf("%d bytes", d.bytes), labels)
	case kindResource:
		return join(d.app, fmt.Sprintf("%.0f%% cpu peak", d.cpuMax), fmt.Sprintf("%d MB", d.rssKB/1024))
	case kindAIAppStarted, kindAIAppStopped, kindAISiteOpened, kindAISiteClosed:
		return d.app
	default:
		return join(d.agentKind, d.toolClass, d.dest, d.app)
	}
}
