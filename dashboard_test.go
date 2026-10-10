package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newDashboardServer(t *testing.T, events []metricEvent) *dashboardServer {
	t.Helper()
	db := readOnly(t, writeMetrics(t, events))
	return &dashboardServer{db: db, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), stallMs: defaultStallMs}
}

func TestDashboardMetricsAPI(t *testing.T) {
	srv := httptest.NewServer(newDashboardServer(t, sampleEvents()).handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/metrics?from=2026-10-09T12:00:00Z&to=2026-10-09T13:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var rep metricsReport
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Decisions.Total != 4 || rep.Clipboard.Sensitive != 2 {
		t.Errorf("report decisions=%d sensitive=%d", rep.Decisions.Total, rep.Clipboard.Sensitive)
	}

	// Bad window is a 400, not a 500.
	bad, _ := http.Get(srv.URL + "/api/metrics?from=notatime")
	if bad.StatusCode != 400 {
		t.Errorf("bad from = %d", bad.StatusCode)
	}
}

func TestDashboardTimelineAPI(t *testing.T) {
	srv := httptest.NewServer(newDashboardServer(t, sampleEvents()).handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/timeline?from=2026-10-09T12:00:00Z&to=2026-10-09T13:00:00Z&buckets=12")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tl timeline
	if err := json.NewDecoder(resp.Body).Decode(&tl); err != nil {
		t.Fatal(err)
	}
	if len(tl.Points) == 0 {
		t.Fatal("no points")
	}
	var events, decisions, sensitive int
	for _, p := range tl.Points {
		events += p.Events
		decisions += p.Decisions
		sensitive += p.Sensitive
	}
	if events != len(sampleEvents()) || decisions != 4 || sensitive != 3 {
		t.Errorf("timeline totals events=%d decisions=%d sensitive=%d", events, decisions, sensitive)
	}
}

func TestDashboardServesPage(t *testing.T) {
	srv := httptest.NewServer(newDashboardServer(t, nil).handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"agent11 activity", "/api/metrics", "/api/timeline"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("page missing %q", want)
		}
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("no CSP header")
	}
	// Unknown paths are 404, not the page.
	nf, _ := http.Get(srv.URL + "/secret")
	if nf.StatusCode != 404 {
		t.Errorf("unknown path = %d", nf.StatusCode)
	}
}

func TestDashboardHTMLNoBacktick(t *testing.T) {
	if strings.Contains(dashboardHTML, "`") {
		t.Error("dashboard HTML contains a backtick, which breaks the Go raw string")
	}
}

func TestStartDashboardLoopbackOnly(t *testing.T) {
	err := startDashboard(context.Background(), "0.0.0.0:0", "x", defaultStallMs, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("err = %v", err)
	}
}

func TestQueryTimelineBuckets(t *testing.T) {
	db := readOnly(t, writeMetrics(t, sampleEvents()))
	f := metricsFilters{FromMs: at(0).UnixMilli(), ToMs: at(60).UnixMilli()}
	tl, err := queryTimeline(db, f, 6, at(60))
	if err != nil {
		t.Fatal(err)
	}
	if tl.BucketMs != 10*60_000 {
		t.Errorf("bucket = %d ms", tl.BucketMs)
	}
	// Every sample event falls in the first 21 minutes, so the first three
	// 10-minute buckets hold them all.
	var first3 int
	for i := 0; i < 3 && i < len(tl.Points); i++ {
		first3 += tl.Points[i].Events
	}
	if first3 != len(sampleEvents()) {
		t.Errorf("first 3 buckets = %d, want %d", first3, len(sampleEvents()))
	}
}
