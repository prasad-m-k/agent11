package main

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// The metrics store keeps agent11's activity in a local SQLite database so it
// can be queried now (agent11 metrics query) and drawn in a dashboard later.
// Like c11's journal it is body-free: rows hold kinds, labels, counts, and
// timings, never clipboard text, prompts, request bodies, or command lines.
//
// Writes never wait on disk: Record hands an event to a buffered channel and
// one writer goroutine commits batches. A full buffer drops the event and
// counts the drop, so a stalled disk cannot stall the proxy.

const (
	metricsSchemaVersion = 3
	metricsBuffer        = 4096
	metricsBatch         = 256
	metricsFlushEvery    = time.Second
	metricsPruneEvery    = time.Hour
	metricsPruneChunk    = 1000
)

// Event kinds. Lifecycle kinds bound AI usage intervals across restarts.
const (
	kindAgentStarted   = "agent_started"
	kindAgentStopped   = "agent_stopped"
	kindDecision       = "decision"
	kindClipboard      = "clipboard"
	kindClipboardGuard = "clipboard_guarded"
	kindIntake         = "intake"
	kindAIAppStarted   = "ai_app_started"
	kindAIAppStopped   = "ai_app_stopped"
	kindAISiteOpened   = "ai_site_opened"
	kindAISiteClosed   = "ai_site_closed"
	kindPolicyReload   = "policy_reload"
	kindResource       = "resource_sample"
	kindTokenUsage     = "token_usage"
)

// metricEvent is one row. Fields that do not apply to a kind stay zero and are
// stored as NULL.
type metricEvent struct {
	At            time.Time
	Kind          string
	Verdict       string
	Applied       string
	Enforced      bool
	Mode          string
	Dest          string // upstream host, or the site an intake caller named
	Category      string
	AgentID       string
	AgentIDSource string
	App           string // AI app name, AI site host, or intake source label
	Classifier    string
	Bytes         int
	Latency       time.Duration
	Confidence    float64
	Classes       []string
	Rules         []finding // rule names with counts

	// Token usage, read from the LLM response's usage field by the proxy.
	// Integers only; the response text is never stored.
	InTokens  int64
	OutTokens int64

	// Agent lifecycle (from hooks) and request metadata (from the proxy).
	// Every value is an opaque ID or a name, never content.
	SessionID string
	AgentKind string
	Model     string
	Provider  string
	TurnID    string
	RequestID string
	ToolClass string

	// Resource samples: one per AI app per resourceWindow.
	CPUPct float64 // mean %CPU over the window, as ps reports it
	CPUMax float64
	RSSKB  int64 // peak resident memory
	Procs  int
}

// recorder takes metric events. Components hold one so the store stays
// optional: nopRecorder discards everything.
type recorder interface {
	Record(metricEvent)
}

type nopRecorder struct{}

func (nopRecorder) Record(metricEvent) {}

// decisionEvent converts a proxy decision, which is already content-free.
func decisionEvent(e Event, latency time.Duration) metricEvent {
	d := e.Decision
	rules := make([]finding, len(d.Rules))
	for i, r := range d.Rules {
		rules[i] = finding{rule: r, count: 1}
	}
	return metricEvent{
		At: e.Time, Kind: kindDecision, Verdict: d.Verdict.String(), Applied: d.Applied.String(),
		Enforced: d.enforced(), Mode: d.Mode, Dest: d.Destination, Category: d.Category,
		AgentID: d.AgentID, AgentIDSource: d.AgentIDSource, Classifier: d.Classifier,
		Latency: latency, Confidence: d.Confidence, Classes: d.Classes, Rules: rules,
		Model: e.Model, Provider: providerFor(d.Destination),
	}
}

type metricsStore struct {
	db        *sql.DB
	logger    *slog.Logger
	retention time.Duration

	mu      sync.RWMutex // guards closed against Record racing Close
	closed  bool
	ch      chan metricEvent
	done    chan struct{}
	dropped atomic.Int64
}

// defaultMetricsPath is <user config dir>/agent11/metrics.sqlite3, e.g.
// ~/Library/Application Support/agent11 on macOS, ~/.config/agent11 on Linux.
func defaultMetricsPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "agent11-metrics.sqlite3"
	}
	return filepath.Join(dir, "agent11", "metrics.sqlite3")
}

// openMetricsStore opens or creates the database and starts the writer.
func openMetricsStore(path string, retention time.Duration, maxBytes int64, logger *slog.Logger) (*metricsStore, error) {
	db, err := openMetricsDB(path, false)
	if err != nil {
		return nil, err
	}
	if err := initMetricsSchema(db, maxBytes); err != nil {
		db.Close()
		return nil, fmt.Errorf("metrics db %s: %w", path, err)
	}
	s := &metricsStore{db: db, logger: logger, retention: retention,
		ch: make(chan metricEvent, metricsBuffer), done: make(chan struct{})}
	if err := s.prune(time.Now()); err != nil {
		logger.Error("metrics prune failed", "err", err)
	}
	go s.run()
	return s, nil
}

// openMetricsDB opens the database file. The file is created 0600 inside a
// 0700 directory before SQLite touches it, so the umask never widens it, and
// a symlink in its place is refused.
func openMetricsDB(path string, readOnly bool) (*sql.DB, error) {
	if readOnly {
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("metrics db: %w", err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("metrics db %s: not a regular file", path)
		}
		db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(1000)&_pragma=query_only(1)")
		if err != nil {
			return nil, err
		}
		var v int
		if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
			db.Close()
			return nil, fmt.Errorf("metrics db %s: %w", path, err)
		}
		if v != metricsSchemaVersion {
			db.Close()
			return nil, fmt.Errorf("metrics db %s: schema version %d, this build reads %d", path, v, metricsSchemaVersion)
		}
		return db, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("metrics dir: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("metrics db %s: not a regular file", path)
	} else if errors.Is(err, fs.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("metrics db: %w", err)
		}
		f.Close()
	}
	db, err := sql.Open("sqlite", "file:"+path+
		"?_pragma=busy_timeout(1000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	// One connection: the writer is the only user, and per-connection pragmas
	// (foreign_keys for cascading deletes) then always apply.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("metrics db %s: %w", path, err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			os.Chmod(path+suffix, 0o600)
		}
	}
	return db, nil
}

func initMetricsSchema(db *sql.DB, maxBytes int64) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v < 0 || v > metricsSchemaVersion {
		return fmt.Errorf("schema version %d, this build writes %d", v, metricsSchemaVersion)
	}
	if v == 0 {
		// auto_vacuum only takes effect before the first table exists.
		if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range []string{
			`CREATE TABLE events (
				seq INTEGER PRIMARY KEY AUTOINCREMENT,
				at_ms INTEGER NOT NULL,
				kind TEXT NOT NULL,
				verdict TEXT, applied TEXT, enforced INTEGER, mode TEXT,
				dest TEXT, category TEXT,
				agent_id TEXT, agent_id_source TEXT,
				app TEXT, classifier TEXT,
				bytes INTEGER, latency_us INTEGER, confidence REAL)`,
			`CREATE INDEX events_time_kind ON events(at_ms, kind)`,
			`CREATE INDEX events_dims ON events(kind, category, agent_id, at_ms)`,
			// One row per class or rule an event carries, so either can be
			// grouped without parsing lists.
			`CREATE TABLE event_labels (
				seq INTEGER NOT NULL REFERENCES events(seq) ON DELETE CASCADE,
				label_kind TEXT NOT NULL,
				value TEXT NOT NULL,
				count INTEGER NOT NULL DEFAULT 1)`,
			`CREATE INDEX event_labels_seq ON event_labels(seq)`,
			`CREATE INDEX event_labels_value ON event_labels(label_kind, value)`,
			`CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)`,
			`INSERT INTO meta VALUES ('dropped_events', 0), ('created_at_ms', ` + fmt.Sprint(time.Now().UnixMilli()) + `)`,
			`PRAGMA user_version=1`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		v = 1
	}
	if v == 1 {
		// Version 2: agent lifecycle, request metadata, and resource samples.
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range []string{
			`ALTER TABLE events ADD COLUMN session_id TEXT`,
			`ALTER TABLE events ADD COLUMN agent_kind TEXT`,
			`ALTER TABLE events ADD COLUMN model TEXT`,
			`ALTER TABLE events ADD COLUMN provider TEXT`,
			`ALTER TABLE events ADD COLUMN turn_id TEXT`,
			`ALTER TABLE events ADD COLUMN request_id TEXT`,
			`ALTER TABLE events ADD COLUMN tool_class TEXT`,
			`ALTER TABLE events ADD COLUMN cpu_pct REAL`,
			`ALTER TABLE events ADD COLUMN cpu_max REAL`,
			`ALTER TABLE events ADD COLUMN rss_kb INTEGER`,
			`ALTER TABLE events ADD COLUMN procs INTEGER`,
			`CREATE INDEX events_session ON events(session_id, seq)`,
			`PRAGMA user_version=2`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migrate to version 2: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		v = 2
	}
	if v == 2 {
		// Version 3: token usage read from LLM responses.
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range []string{
			`ALTER TABLE events ADD COLUMN input_tokens INTEGER`,
			`ALTER TABLE events ADD COLUMN output_tokens INTEGER`,
			`PRAGMA user_version=3`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migrate to version 3: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	if maxBytes > 0 {
		var pageSize int64
		if err := db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
			return err
		}
		if _, err := db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", max(1, maxBytes/pageSize))); err != nil {
			return err
		}
	}
	return nil
}

// Record queues an event. It never blocks: when the buffer is full, or the
// store is closed, the event is dropped and counted.
func (s *metricsStore) Record(e metricEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Close flushes queued events, records the drop count, and closes the database.
func (s *metricsStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()
	<-s.done
	return s.db.Close()
}

func (s *metricsStore) run() {
	defer close(s.done)
	flush := time.NewTicker(metricsFlushEvery)
	defer flush.Stop()
	prune := time.NewTicker(metricsPruneEvery)
	defer prune.Stop()

	var batch []metricEvent
	var lastErr string
	write := func() {
		err := s.insert(batch)
		if n := s.dropped.Swap(0); n > 0 {
			if _, derr := s.db.Exec(`UPDATE meta SET value = value + ? WHERE key = 'dropped_events'`, n); derr != nil {
				s.dropped.Add(n)
			}
		}
		if err != nil {
			s.dropped.Add(int64(len(batch)))
			if err.Error() != lastErr {
				s.logger.Error("metrics write failed", "err", err, "events", len(batch))
				lastErr = err.Error()
			}
		} else {
			lastErr = ""
		}
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				write()
				return
			}
			batch = append(batch, e)
			if len(batch) >= metricsBatch {
				write()
			}
		case <-flush.C:
			if len(batch) > 0 {
				write()
			}
		case <-prune.C:
			if err := s.prune(time.Now()); err != nil {
				s.logger.Error("metrics prune failed", "err", err)
			}
		}
	}
}

func (s *metricsStore) insert(batch []metricEvent) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ev, err := tx.Prepare(`INSERT INTO events (at_ms, kind, verdict, applied, enforced, mode, dest, category,
		agent_id, agent_id_source, app, classifier, bytes, latency_us, confidence,
		session_id, agent_kind, model, provider, turn_id, request_id, tool_class, cpu_pct, cpu_max, rss_kb, procs,
		input_tokens, output_tokens)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ev.Close()
	lab, err := tx.Prepare(`INSERT INTO event_labels (seq, label_kind, value, count) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer lab.Close()

	for _, e := range batch {
		var enforced, latency, bytes, confidence any
		if e.Kind == kindDecision {
			enforced, latency, confidence = boolInt(e.Enforced), e.Latency.Microseconds(), e.Confidence
		}
		if e.Bytes > 0 {
			bytes = e.Bytes
		}
		var cpu, cpuMax, rss, procs, inTok, outTok any
		if e.Kind == kindResource {
			cpu, cpuMax, rss, procs = e.CPUPct, e.CPUMax, e.RSSKB, e.Procs
		}
		if e.Kind == kindTokenUsage {
			inTok, outTok = e.InTokens, e.OutTokens
		}
		res, err := ev.Exec(e.At.UnixMilli(), e.Kind, nullStr(e.Verdict), nullStr(e.Applied), enforced, nullStr(e.Mode),
			nullStr(e.Dest), nullStr(e.Category), nullStr(e.AgentID), nullStr(e.AgentIDSource), nullStr(e.App),
			nullStr(e.Classifier), bytes, latency, confidence,
			nullStr(e.SessionID), nullStr(e.AgentKind), nullStr(e.Model), nullStr(e.Provider), nullStr(e.TurnID),
			nullStr(e.RequestID), nullStr(e.ToolClass), cpu, cpuMax, rss, procs, inTok, outTok)
		if err != nil {
			return err
		}
		seq, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for _, c := range e.Classes {
			if _, err := lab.Exec(seq, "class", c, 1); err != nil {
				return err
			}
		}
		for _, r := range e.Rules {
			if _, err := lab.Exec(seq, "rule", r.rule, max(r.count, 1)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// prune deletes events older than the retention window in small batches, so a
// large backlog never holds the write lock for long; labels go by cascade.
func (s *metricsStore) prune(now time.Time) error {
	if s.retention <= 0 {
		return nil
	}
	cutoff := now.Add(-s.retention).UnixMilli()
	for {
		res, err := s.db.Exec(`DELETE FROM events WHERE seq IN
			(SELECT seq FROM events WHERE at_ms < ? ORDER BY seq LIMIT ?)`, cutoff, metricsPruneChunk)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n < metricsPruneChunk {
			break
		}
	}
	_, err := s.db.Exec(`PRAGMA incremental_vacuum(256)`)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
