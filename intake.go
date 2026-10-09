package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxIntakeBytes caps a single POST body. Prompts can be long, but this stops
// a runaway or hostile caller from exhausting memory.
const maxIntakeBytes = 4 << 20 // 4 MiB

// intakeRequest is the JSON a caller (browser extension, script) POSTs to
// /scan. Only text is required; source and site are labels for the log.
type intakeRequest struct {
	Source string `json:"source"`
	Site   string `json:"site"`
	Text   string `json:"text"`
}

type intakeResponse struct {
	Flagged  bool      `json:"flagged"`
	Findings []finding `json:"findings"`
}

func (f finding) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Rule  string `json:"rule"`
		Count int    `json:"count"`
	}{f.rule, f.count})
}

// newToken returns a random 32-hex-char token for the intake endpoint.
func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// isLoopback reports whether host resolves only to loopback, so the endpoint
// is never accidentally exposed to the network.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// startIntake runs the local scan server until ctx is cancelled. addr must be a
// loopback address. Every request must carry the bearer token.
func startIntake(ctx context.Context, addr, token string, logger *slog.Logger, scanner *dlpScanner, logContent bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if !isLoopback(host) {
		return fmt.Errorf("refusing to bind non-loopback address %q; use 127.0.0.1 or [::1]", addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if !authorized(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxIntakeBytes)
		var req intakeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}

		findings := scanner.scan(req.Text)
		source := firstNonEmpty(req.Source, "intake")
		attrs := []any{"source", source, "bytes", len(req.Text)}
		if req.Site != "" {
			attrs = append(attrs, "site", req.Site)
		}
		if len(findings) > 0 {
			attrs = append(attrs, "dlp", summary(findings))
		}
		if logContent {
			attrs = append(attrs, "text", req.Text)
		}
		if len(findings) > 0 {
			logger.Warn("intake", attrs...)
		} else {
			logger.Info("intake", attrs...)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(intakeResponse{Flagged: len(findings) > 0, Findings: findings})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	logger.Info("intake listening", "addr", addr)

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

// authorized checks the bearer token in constant time.
func authorized(r *http.Request, token string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" {
		got = r.Header.Get("X-Firetail-Token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
