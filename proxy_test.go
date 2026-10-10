package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestProxy returns a proxy whose upstream is a local TLS test server.
func newTestProxy(t *testing.T, upstream http.Handler, modeFlag string, clf Classifier) (*llmProxy, *bytes.Buffer, string) {
	t.Helper()
	up := httptest.NewTLSServer(upstream)
	t.Cleanup(up.Close)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	d := newDecider(mustPolicy(t, testPolicyJSON), clf, 50*time.Millisecond, modeFlag)
	p := newLLMProxy(d, logSink{logger}, logger, 1<<10)
	p.transport = up.Client().Transport
	p.allowLoopback = true
	return p, &logs, strings.TrimPrefix(up.URL, "https://")
}

func post(p http.Handler, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestProxyBlockResponse(t *testing.T) {
	upstreamHit := false
	p, logs, host := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstreamHit = true }), modeEnforce, nil)
	body := `{"messages":[{"role":"user","content":"Plan for ProjectX"}]}`
	w := post(p, "/"+host+"/v1/messages", body, nil)

	if w.Code != http.StatusForbidden || upstreamHit {
		t.Fatalf("status = %d, upstreamHit = %v", w.Code, upstreamHit)
	}
	var resp struct {
		Type  string `json:"type"`
		Error struct{ Type, Message string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Type != "error" || resp.Error.Type != "permission_error" ||
		!strings.Contains(resp.Error.Message, "code") || !strings.Contains(resp.Error.Message, "engineering") {
		t.Errorf("response = %+v", resp)
	}
	if strings.Contains(w.Body.String(), "Plan for") {
		t.Error("block response echoes request content")
	}
	if !strings.Contains(logs.String(), `msg="request blocked"`) {
		t.Errorf("log = %s", logs)
	}
}

func TestProxyReportModeForwards(t *testing.T) {
	var gotPath, gotLabels, gotBody string
	p, logs, host := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotLabels = r.URL.Path, r.Header.Get(headerLabels)
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		fmt.Fprint(w, `{"ok":true}`)
	}), "", nil)
	body := `{"content":"ProjectX"}`
	w := post(p, "/"+host+"/v1/messages", body, map[string]string{headerLabels: "repo:core", "Authorization": "Bearer sk-secret-value"})

	if w.Code != http.StatusOK || gotPath != "/v1/messages" || gotBody != body {
		t.Fatalf("status=%d path=%q body=%q", w.Code, gotPath, gotBody)
	}
	if gotLabels != "" {
		t.Error("agent11 headers must not reach the upstream")
	}
	l := logs.String()
	if !strings.Contains(l, `msg="request flagged"`) || !strings.Contains(l, "enforced=false") || !strings.Contains(l, "verdict=block") {
		t.Errorf("log = %s", l)
	}
}

func TestProxyLogsNoContentOrKeys(t *testing.T) {
	p, logs, host := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), modeEnforce, nil)
	secretText := "ProjectX " + testAWSKey + " quarterly numbers"
	post(p, "/"+host+"/v1/messages", `{"content":"`+secretText+`"}`, map[string]string{"Authorization": "Bearer sk-ant-api-key-value-xyz"})
	post(p, "/"+host+"/v1/messages", `{"content":"plain question"}`, map[string]string{"x-api-key": "sk-ant-api-key-value-xyz"})
	for _, frag := range []string{testAWSKey, "quarterly", "plain question", "sk-ant-api-key-value-xyz"} {
		if strings.Contains(logs.String(), frag) {
			t.Errorf("log contains %q:\n%s", frag, logs)
		}
	}
}

func TestProxyStreamingPassthrough(t *testing.T) {
	release := make(chan struct{})
	p, _, host := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: one\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "event: two\ndata: {}\n\n")
	}), "", nil)
	front := httptest.NewServer(p)
	defer front.Close()

	resp, err := http.Post(front.URL+"/"+host+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "event: one\n" {
		t.Fatalf("first event not flushed before the stream ended: %q, %v", line, err)
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "event: two") {
		t.Errorf("rest = %q", rest)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type = %q", ct)
	}
}

func TestProxyBodyCap(t *testing.T) {
	p, _, host := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("oversized body reached the upstream")
	}), "", nil)
	w := post(p, "/"+host+"/v1/messages", `{"content":"`+strings.Repeat("a", 2<<10)+`"}`, nil)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d", w.Code)
	}
}

func TestProxyRejectsBadUpstreams(t *testing.T) {
	p, _, _ := newTestProxy(t, http.NotFoundHandler(), "", nil)
	p.allowLoopback = false
	for path, want := range map[string]int{
		"/":                     http.StatusNotFound,
		"/user@evil.example/v1": http.StatusNotFound,
		"/127.0.0.1:8788/v1/x":  http.StatusForbidden,
		"/localhost/v1/x":       http.StatusForbidden,
		"/..%2f..%2fetc/passwd": http.StatusNotFound,
	} {
		if w := post(p, path, "{}", nil); w.Code != want {
			t.Errorf("%s: status = %d, want %d", path, w.Code, want)
		}
	}
}

func TestProxyClassifierTimeoutForwards(t *testing.T) {
	forwarded := false
	slow := &fakeClassifier{probs: map[string]float64{"code": 1}, delay: time.Second}
	p, logs, host := newTestProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }), modeEnforce, slow)
	start := time.Now()
	w := post(p, "/"+host+"/v1/messages", `{"content":"ambiguous text"}`, nil)
	if time.Since(start) > 500*time.Millisecond {
		t.Error("classifier timeout did not bound the request")
	}
	if w.Code != http.StatusOK || !forwarded {
		t.Errorf("status = %d, forwarded = %v; unlabeled text should fall back to allow", w.Code, forwarded)
	}
	if !strings.Contains(logs.String(), "classifier=unavailable") {
		t.Errorf("log = %s", logs)
	}
}

func TestStartProxyLoopbackOnly(t *testing.T) {
	err := startProxy(context.Background(), "0.0.0.0:0", &llmProxy{logger: slog.Default()})
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("err = %v", err)
	}
}

func TestRequestText(t *testing.T) {
	blob := strings.Repeat("A", 2000)
	got := requestText([]byte(`{"b":"second","a":["first",{"img":"` + blob + `"}],"n":3}`))
	if got != "first\nsecond\n" {
		t.Errorf("text = %q", got)
	}
	if requestText([]byte("not json")) != "not json" {
		t.Error("plain text body")
	}
}
