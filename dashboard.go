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
