// Command agent11 watches the system clipboard and running AI/LLM apps,
// and appends each change to a rotating log file.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
)

// readTimeout bounds a single clipboard read so a hung helper tool
// (xclip is known to do this) cannot stall the loop.
const readTimeout = 3 * time.Second

// clipboardCommands returns candidate commands for reading the clipboard on
// the current OS, in order of preference.
func clipboardCommands() [][]string {
	switch runtime.GOOS {
	case "darwin":
		return [][]string{{"pbpaste"}}
	case "windows":
		return [][]string{{"powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"}}
	default:
		return [][]string{
			{"wl-paste", "--no-newline"},
			{"xclip", "-selection", "clipboard", "-o"},
			{"xsel", "--clipboard", "--output"},
		}
	}
}

func readClipboard(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	var errs []error
	for _, args := range clipboardCommands() {
		if _, err := exec.LookPath(args[0]); err != nil {
			errs = append(errs, err)
			continue
		}
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", args[0], err))
			continue
		}
		return out, nil
	}
	return nil, fmt.Errorf("no usable clipboard tool: %w", errors.Join(errs...))
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "metrics" {
		os.Exit(runMetricsCLI(os.Args[2:], os.Stdout, os.Stderr, time.Now()))
	}
	if len(os.Args) > 1 && os.Args[1] == "dashboard" {
		os.Exit(runDashboardCLI(os.Args[2:], os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "hook" {
		rest := os.Args[2:]
		// Custom agents are defined as JSON in the adapters directory.
		adaptersDir := defaultAdaptersDir()
		for i := 0; i < len(rest)-1; i++ {
			if rest[i] == "--adapters" {
				adaptersDir = rest[i+1]
			}
		}
		if slices.Contains(rest, "--list-agents") {
			for _, err := range loadCustomAdapters(adaptersDir) {
				fmt.Fprintln(os.Stderr, "adapter warning:", err)
			}
			fmt.Println("agents agent11 can hook (built-in + adapters in " + adaptersDir + "):")
			for _, name := range knownAgents() {
				style := "built-in"
				if a := customAdapters[name]; a != nil {
					style = "custom (" + a.ConfigStyle + ")"
				}
				fmt.Printf("  %-16s %s\n", name, style)
			}
			return
		}
		if pc := slices.Index(rest, "--print-config"); pc >= 0 {
			exe, err := os.Executable()
			if err != nil {
				exe = "agent11"
			}
			agent := hookAgentKindClaude
			if pc+1 < len(rest) && !strings.HasPrefix(rest[pc+1], "-") {
				agent = rest[pc+1]
			}
			if agent != hookAgentKindClaude && agent != hookAgentKindAntigrav {
				for _, e := range loadCustomAdapters(adaptersDir) {
					fmt.Fprintln(os.Stderr, "adapter warning:", e)
				}
			}
			out, err := hooksSnippet(agent, exe)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(2)
			}
			fmt.Fprintln(os.Stderr, hookConfigDest(agent))
			fmt.Println(out)
			return
		}
		os.Exit(runHookCLI(rest, os.Stdin, time.Now()))
	}
	interval := flag.Duration("interval", 500*time.Millisecond, "how often to poll the clipboard")
	once := flag.Bool("once", false, "print the current clipboard to stdout and exit")
	logPath := flag.String("log", "agent11.log", "log file path")
	maxMB := flag.Float64("max-mb", 10, "rotate after the log reaches this many MB (0 = no size limit)")
	maxLines := flag.Int64("max-lines", 10000, "rotate after the log reaches this many lines (0 = no line limit)")
	maxBackups := flag.Int("max-backups", 5, "number of rotated files to keep")
	quiet := flag.Bool("quiet", false, "write to the log file only, not the console")
	aiInterval := flag.Duration("ai-interval", 5*time.Second, "how often to scan for AI/LLM apps (0 = disabled)")
	watchBrowser := flag.Bool("browser", true, "also log AI sites open in Chrome tabs (macOS only)")
	logContent := flag.Bool("log-content", true, "log captured clipboard text; false = log DLP findings only, never the raw content")
	keywords := flag.String("dlp-keywords", "", "comma-separated confidential markers to flag (e.g. a project codename)")
	listen := flag.String("listen", "", "loopback address for the DLP scan endpoint, e.g. 127.0.0.1:8787 (empty = disabled)")
	intakeToken := flag.String("intake-token", "", "bearer token required by the scan endpoint (generated if empty)")
	policyPath := flag.String("policy", "", "company data policy file, JSON (required by -proxy and -eval)")
	proxyAddr := flag.String("proxy", "", "loopback address for the LLM reverse proxy, e.g. 127.0.0.1:8788 (empty = disabled)")
	proxyMaxMB := flag.Float64("proxy-max-mb", 32, "largest request body the proxy will scan and forward, in MB")
	mode := flag.String("mode", "", "report or enforce; overrides the policy's global mode (per-class modes still win)")
	evalDir := flag.String("eval", "", "score the policy against a labeled corpus directory, print the results, and exit")
	classifierName := flag.String("classifier", "none", "classifier for ambiguous text: none or jev (jev reads OPENROUTER_API_KEY)")
	classifierModel := flag.String("classifier-model", jevDefaultModel, "pinned classifier model ID")
	classifierTimeout := flag.Duration("classifier-timeout", 2*time.Second, "longest the classifier may hold up a request")
	guardMode := flag.String("clipboard-guard", guardOff, "replace a sensitive clipboard with a notice: off, ai (while an AI site or desktop AI app is open), or always")
	guardRules := flag.String("guard-rules", defaultGuardRules, "DLP rules that trigger the clipboard guard; keyword:* means every -dlp-keywords marker")
	metricsOn := flag.Bool("metrics", true, "record body-free metrics in a local SQLite database (read with: agent11 metrics query)")
	metricsPath := flag.String("metrics-db", defaultMetricsPath(), "metrics database path")
	metricsRetention := flag.Duration("metrics-retention", 14*24*time.Hour, "how long metrics are kept")
	metricsMaxMB := flag.Int64("metrics-max-mb", 256, "size cap for the metrics database, in MB")
	hooksOn := flag.Bool("hooks", true, "accept agent lifecycle events from \"agent11 hook\" on a private Unix socket (needs -metrics)")
	hookSocket := flag.String("hook-socket", defaultHookSocket(), "Unix socket for agent lifecycle hooks")
	dashboardAddr := flag.String("dashboard", "127.0.0.1:9090", "serve the metrics dashboard on this loopback address (empty = off; needs -metrics)")
	flag.Parse()

	scanner := newDLPScanner(strings.Split(*keywords, ","))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *mode != "" && *mode != modeReport && *mode != modeEnforce {
		fmt.Fprintf(os.Stderr, "error: -mode %q is not report or enforce\n", *mode)
		os.Exit(2)
	}
	guard, err := newClipboardGuard(*guardMode, *guardRules)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if guard.mode == guardAI && *aiInterval <= 0 {
		fmt.Fprintln(os.Stderr, "error: -clipboard-guard ai needs -ai-interval > 0 to know when AI tools are open")
		os.Exit(2)
	}
	if (*proxyAddr != "" || *evalDir != "") && *policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: -proxy and -eval need -policy")
		os.Exit(2)
	}
	var dec *decider
	if *policyPath != "" {
		// An invalid policy at startup is fatal; only reloads fall back.
		pol, err := loadPolicy(*policyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		clf, err := newClassifier(*classifierName, *classifierModel)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		dec = newDecider(pol, clf, *classifierTimeout, *mode)
	}

	if *evalDir != "" {
		samples, err := loadCorpus(*evalDir)
		if err == nil {
			dec.exhaustive = true
			err = runEval(ctx, dec, samples, os.Stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: eval:", err)
			os.Exit(1)
		}
		return
	}

	if *once {
		data, err := readClipboard(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		os.Stdout.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			fmt.Println()
		}
		return
	}

	logFile, err := openRotatingFile(*logPath, int64(*maxMB*1024*1024), *maxLines, *maxBackups)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: open log:", err)
		os.Exit(1)
	}
	defer logFile.Close()

	var out io.Writer = logFile
	if !*quiet {
		out = io.MultiWriter(logFile, os.Stdout)
	}
	// logfmt lines: one entry per line, with newlines and control characters
	// in the clipboard text escaped inside the quoted text= value.
	logger := slog.New(slog.NewTextHandler(out, nil))

	// Fail fast if no clipboard tool is usable at all; after this, read
	// errors are logged and polling continues.
	last, err := readClipboard(ctx)
	if err != nil {
		logger.Error("clipboard unavailable", "err", err)
		os.Exit(1)
	}
	var rec recorder = nopRecorder{}
	var store *metricsStore
	if *metricsOn {
		store, err = openMetricsStore(*metricsPath, *metricsRetention, *metricsMaxMB*1024*1024, logger)
		if err != nil {
			logger.Error("metrics unavailable", "err", err)
			os.Exit(1)
		}
		rec = store
		defer store.Close()
	}
	rec.Record(metricEvent{Kind: kindAgentStarted})

	startAttrs := []any{"interval", *interval, "log", *logPath,
		"max_mb", *maxMB, "max_lines", *maxLines, "max_backups", *maxBackups, "ai_interval", *aiInterval,
		"clipboard_guard", guard.mode}
	if dec != nil {
		pol := dec.policy.Load()
		startAttrs = append(startAttrs, "policy", *policyPath, "proxy", *proxyAddr, "proxy_max_mb", *proxyMaxMB,
			"mode", dec.modeFor(pol, nil), "classifier", dec.classifier.Name(), "classifier_timeout", *classifierTimeout)
		// Raw content to a hosted classifier is an explicit policy choice; make it visible.
		if raw := pol.rawClassifierClasses(); len(raw) > 0 && *classifierName != "none" {
			startAttrs = append(startAttrs, "classifier_raw", strings.Join(raw, ","))
		}
	}
	if store != nil {
		startAttrs = append(startAttrs, "metrics_db", *metricsPath, "metrics_retention", *metricsRetention)
		if *hooksOn {
			startAttrs = append(startAttrs, "hook_socket", *hookSocket)
		}
		if *dashboardAddr != "" {
			startAttrs = append(startAttrs, "dashboard", *dashboardAddr)
		}
	}
	logger.Info("agent11 started", startAttrs...)

	intakeErrCh := make(chan error, 2)
	if *listen != "" {
		token := *intakeToken
		if token == "" {
			token = newToken()
			// Printed to stderr, never the log file, so the token is not
			// persisted alongside the data it protects.
			fmt.Fprintf(os.Stderr, "agent11: intake token: %s\n", token)
		}
		go func() {
			if err := startIntake(ctx, *listen, token, logger, scanner, *logContent, rec); err != nil {
				logger.Error("intake endpoint failed", "err", err)
				intakeErrCh <- err
				stop() // a requested endpoint that cannot start ends the program
			}
		}()
	}
	if store != nil && *hooksOn {
		go func() {
			if err := startHookServer(ctx, *hookSocket, rec, logger); err != nil {
				// Lifecycle metrics are optional; the rest of agent11 keeps running.
				logger.Error("hook socket failed", "err", err)
			}
		}()
	}
	if store != nil && *dashboardAddr != "" {
		// Reads the same database read-only; WAL mode allows it alongside the
		// writer. A bind failure is logged but does not stop collection.
		go func() {
			if err := startDashboard(ctx, *dashboardAddr, *metricsPath, defaultStallMs, logger); err != nil {
				logger.Error("dashboard failed", "err", err)
			}
		}()
	}
	if *proxyAddr != "" {
		p := newLLMProxy(dec, logSink{logger}, logger, int64(*proxyMaxMB*1024*1024))
		p.rec = rec
		go func() {
			if err := startProxy(ctx, *proxyAddr, p); err != nil {
				logger.Error("proxy failed", "err", err)
				intakeErrCh <- err
				stop()
			}
		}()
	}
	var policyTick <-chan time.Time
	var policyMod time.Time
	var lastPolicyErr string
	if dec != nil {
		if fi, err := os.Stat(*policyPath); err == nil {
			policyMod = fi.ModTime()
		}
		t := time.NewTicker(policyReloadInterval)
		defer t.Stop()
		policyTick = t.C
	}

	var aiTick <-chan time.Time
	var ai *aiWatcher
	var browser *browserWatcher
	var lastAIErr, lastBrowserErr string
	if *aiInterval > 0 {
		ai = newAIWatcher(logger)
		ai.rec = rec
		if err := ai.scan(ctx, true); err != nil {
			logger.Error("process scan failed", "err", err)
			lastAIErr = err.Error()
		}
		if *watchBrowser {
			browser = newBrowserWatcher(logger)
			browser.rec = rec
			if err := browser.scan(ctx, true); err != nil {
				logger.Error("browser scan failed", "err", err)
				lastBrowserErr = err.Error()
			}
		}
		t := time.NewTicker(*aiInterval)
		defer t.Stop()
		aiTick = t.C
	}

	aiContext := func() bool {
		return (browser != nil && browser.anyOpen()) || (ai != nil && ai.anyDesktop())
	}
	// handleClipboard logs a new clipboard value, or guards it, and returns
	// what the clipboard now holds.
	handleClipboard := func(data []byte) []byte {
		findings := scanner.scan(string(data))
		hit := guard.trigger(findings, aiContext())
		if len(hit) == 0 {
			logClipboard(logger, scanner, *logContent, data)
			rec.Record(metricEvent{Kind: kindClipboard, Bytes: len(data), Rules: findings})
			return data
		}
		notice := []byte(guardNotice(hit))
		if err := writeClipboard(ctx, notice); err != nil {
			logger.Error("clipboard guard failed", "err", err, "dlp", summary(hit))
			logClipboard(logger, scanner, *logContent, data)
			rec.Record(metricEvent{Kind: kindClipboard, Bytes: len(data), Rules: findings})
			return data
		}
		// The guarded text is never logged, whatever -log-content says: the
		// guard exists to keep it from going anywhere.
		logger.Warn("clipboard guarded", "bytes", len(data), "dlp", summary(hit), "mode", guard.mode)
		rec.Record(metricEvent{Kind: kindClipboardGuard, Bytes: len(data), Rules: hit, Mode: guard.mode})
		return notice
	}
	if len(last) > 0 {
		last = handleClipboard(last)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			logger.Info("agent11 stopped")
			rec.Record(metricEvent{Kind: kindAgentStopped})
			select {
			case <-intakeErrCh:
				if store != nil {
					store.Close() // os.Exit skips deferred calls
				}
				os.Exit(1) // the intake endpoint or proxy failed to start
			default:
			}
			return
		case <-policyTick:
			fi, err := os.Stat(*policyPath)
			if err == nil && fi.ModTime().Equal(policyMod) {
				continue
			}
			var pol *Policy
			if err == nil {
				pol, err = loadPolicy(*policyPath)
			}
			if err != nil {
				// Keep the last good policy; log each distinct problem once.
				if err.Error() != lastPolicyErr {
					logger.Error("policy reload failed, keeping last good policy", "err", err)
					lastPolicyErr = err.Error()
				}
				continue
			}
			policyMod, lastPolicyErr = fi.ModTime(), ""
			dec.policy.Store(pol)
			logger.Info("policy reloaded", "policy", *policyPath, "classes", len(pol.Classes))
			rec.Record(metricEvent{Kind: kindPolicyReload})
			continue
		case <-aiTick:
			if err := ai.scan(ctx, false); err != nil {
				if ctx.Err() == nil && err.Error() != lastAIErr {
					logger.Error("process scan failed", "err", err)
					lastAIErr = err.Error()
				}
			} else {
				lastAIErr = ""
			}
			if browser != nil {
				if err := browser.scan(ctx, false); err != nil {
					if ctx.Err() == nil && err.Error() != lastBrowserErr {
						logger.Error("browser scan failed", "err", err)
						lastBrowserErr = err.Error()
					}
				} else {
					lastBrowserErr = ""
				}
			}
			continue
		case <-ticker.C:
		}

		data, err := readClipboard(ctx)
		if err != nil {
			if ctx.Err() != nil {
				continue // shutting down; the select above will exit
			}
			// Log each distinct error once rather than on every tick.
			if err.Error() != lastErr {
				logger.Error("clipboard read failed", "err", err)
				lastErr = err.Error()
			}
			continue
		}
		lastErr = ""
		if len(data) > 0 && !bytes.Equal(data, last) {
			last = handleClipboard(data)
		}
	}
}

// policyReloadInterval is how often the policy file is checked for changes.
const policyReloadInterval = 5 * time.Second

func newClassifier(name, model string) (Classifier, error) {
	switch name {
	case "none", "":
		return noopClassifier{}, nil
	case "jev":
		key := os.Getenv("OPENROUTER_API_KEY")
		if key == "" {
			return nil, errors.New("-classifier jev needs OPENROUTER_API_KEY in the environment")
		}
		return newJevClassifier(model, key), nil
	default:
		return nil, fmt.Errorf("-classifier %q is not none or jev", name)
	}
}

// logClipboard records a clipboard capture. It scans for confidential data
// first; when anything matches, the entry is logged at WARN with a dlp= field.
// With logContent false the raw text is never written, only the findings, so
// the log does not become a store of the data it is meant to protect.
func logClipboard(logger *slog.Logger, scanner *dlpScanner, logContent bool, data []byte) {
	findings := scanner.scan(string(data))
	attrs := []any{"bytes", len(data)}
	if len(findings) > 0 {
		attrs = append(attrs, "dlp", summary(findings))
	}
	if logContent {
		attrs = append(attrs, "text", string(data))
	}
	if len(findings) > 0 {
		logger.Warn("clipboard", attrs...)
	} else {
		logger.Info("clipboard", attrs...)
	}
}
