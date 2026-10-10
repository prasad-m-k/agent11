package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// The LLM reverse proxy. Agents reach it through a base-URL override whose
// first path segment names the upstream host, for example
//
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8788/api.anthropic.com
//	OPENAI_BASE_URL=http://127.0.0.1:8788/api.openai.com/v1
//
// It does no TLS interception: the agent talks plain HTTP to loopback and the
// proxy opens its own HTTPS connection upstream.

const (
	headerLabels = "X-Agent11-Labels"
	headerAgent  = "X-Agent11-Agent"
)

var upstreamHost = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::\d{1,5})?$`)

type llmProxy struct {
	decider   *decider
	sink      Sink
	logger    *slog.Logger
	maxBody   int64
	transport http.RoundTripper

	scheme        string // "https"; tests swap in their own TLS server
	allowLoopback bool   // tests only: production refuses loopback upstreams
}

func newLLMProxy(d *decider, sink Sink, logger *slog.Logger, maxBody int64) *llmProxy {
	return &llmProxy{decider: d, sink: sink, logger: logger, maxBody: maxBody,
		transport: http.DefaultTransport, scheme: "https"}
}

// startProxy serves the proxy on a loopback address until ctx is cancelled.
func startProxy(ctx context.Context, addr string, p *llmProxy) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("proxy address %q: %w", addr, err)
	}
	if !isLoopback(host) {
		return fmt.Errorf("refusing to bind non-loopback address %q; use 127.0.0.1 or [::1]", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	// No ReadTimeout or WriteTimeout: streamed completions can run for minutes.
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	p.logger.Info("proxy listening", "addr", addr)

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

func (p *llmProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !upstreamHost.MatchString(host) {
		writeProxyError(w, http.StatusNotFound, "not_found_error",
			"agent11: the first path segment must be the upstream host, e.g. /api.anthropic.com/v1/messages")
		return
	}
	if h, _, err := net.SplitHostPort(host); (err == nil && isLoopback(h)) || isLoopback(host) {
		if !p.allowLoopback {
			writeProxyError(w, http.StatusForbidden, "permission_error", "agent11: loopback upstreams are not allowed")
			return
		}
	}

	// The body is held only for this request: scanned, forwarded, then dropped.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeProxyError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("agent11: request body over the %d byte scan limit", p.maxBody))
			return
		}
		writeProxyError(w, http.StatusBadRequest, "invalid_request_error", "agent11: could not read request body")
		return
	}

	req := decideRequest{
		Text:        requestText(body),
		Labels:      splitList(r.Header.Get(headerLabels)),
		AgentID:     strings.TrimSpace(r.Header.Get(headerAgent)),
		Destination: host,
	}
	d := p.decider.decide(r.Context(), req)
	if err := p.sink.Emit(Event{Time: time.Now(), Decision: d}); err != nil {
		p.logger.Error("event sink failed", "err", err)
	}

	if d.enforced() {
		writeProxyError(w, http.StatusForbidden, "permission_error", blockMessage(d))
		return
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = p.scheme
			pr.Out.URL.Host = host
			pr.Out.URL.Path = "/" + rest
			pr.Out.URL.RawPath = ""
			pr.Out.Host = host
			pr.Out.Header.Del(headerLabels)
			pr.Out.Header.Del(headerAgent)
			pr.Out.Body = io.NopCloser(bytes.NewReader(body))
			pr.Out.ContentLength = int64(len(body))
		},
		Transport:     p.transport,
		FlushInterval: -1, // flush each write so streamed responses pass through as they arrive
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				p.logger.Error("upstream failed", "dest", host, "err", err)
			}
			writeProxyError(w, http.StatusBadGateway, "api_error", "agent11: upstream request failed")
		},
	}
	rp.ServeHTTP(w, r)
}

// blockMessage tells the user what happened and how to ask for an exception,
// naming classes and owners but never the matched content.
func blockMessage(d Decision) string {
	what := "blocked"
	switch d.Applied {
	case VerdictHold:
		what = "held for approval (approval flow not built yet, so treated as blocked)"
	case VerdictTranslate:
		what = "blocked (surrogate translation not built yet)"
	}
	msg := fmt.Sprintf("agent11: request to %s %s by company data policy; classes: %s.",
		d.Destination, what, strings.Join(d.Classes, ", "))
	if len(d.Owners) > 0 {
		msg += fmt.Sprintf(" To request an exception, contact the class owner: %s.", strings.Join(d.Owners, ", "))
	}
	return msg
}

// writeProxyError writes an error body both the Anthropic and OpenAI SDKs can
// read: each looks for error.message and error.type.
func writeProxyError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": typ, "message": msg},
	})
}

// requestText returns the text an LLM request carries. For JSON it joins every
// string value, so keys and syntax do not trigger patterns; long unbroken
// strings (base64 images, file blobs) are skipped.
func requestText(body []byte) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		if utf8.Valid(body) {
			return string(body)
		}
		return ""
	}
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if len(t) > 1000 && !strings.ContainsAny(t, " \n\t") {
				return
			}
			b.WriteString(t)
			b.WriteByte('\n')
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			// Sorted so the same body always yields the same text.
			for _, k := range slices.Sorted(maps.Keys(t)) {
				walk(t[k])
			}
		}
	}
	walk(v)
	return b.String()
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
