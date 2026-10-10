package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strings"
)

// aiSites lists host suffixes for AI/LLM web apps. A tab is reported when its
// host equals one of these or ends in "."+suffix. Only the host is logged,
// never the path or query, so a page's contents never reach the log.
var aiSites = []string{
	"chatgpt.com",
	"chat.openai.com",
	"claude.ai",
	"gemini.google.com",
	"aistudio.google.com",
	"perplexity.ai",
	"copilot.microsoft.com",
	"poe.com",
	"character.ai",
	"chat.mistral.ai",
	"chat.deepseek.com",
	"grok.com",
	"x.ai",
	"huggingface.co", // chat + spaces
	"pi.ai",
	"you.com",
	"phind.com",
	"chatbot.theb.ai",
}

func matchAISite(host string) (string, bool) {
	host = strings.ToLower(strings.TrimPrefix(host, "www."))
	for _, s := range aiSites {
		if host == s || strings.HasSuffix(host, "."+s) {
			return s, true
		}
	}
	return "", false
}

// chromeTabHosts returns the AI-site hosts currently open in Chrome tabs. It
// returns nil (no error) when Chrome is not running, and is macOS-only for
// now: other browsers and OSes will be added later.
func chromeTabHosts(ctx context.Context) ([]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	// `is running` does not launch Chrome; only URLs are read, not tab content.
	const script = `if application "Google Chrome" is running then
	tell application "Google Chrome"
		set out to ""
		repeat with w in windows
			repeat with t in tabs of w
				set out to out & (URL of t) & linefeed
			end repeat
		end repeat
		return out
	end tell
end if`

	out, err := exec.CommandContext(ctx, "osascript", "-e", script).Output()
	if err != nil {
		return nil, fmt.Errorf("osascript chrome: %w", err)
	}

	seen := map[string]bool{}
	var hosts []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		if site, ok := matchAISite(u.Hostname()); ok && !seen[site] {
			seen[site] = true
			hosts = append(hosts, site)
		}
	}
	slices.Sort(hosts)
	return hosts, nil
}

// browserWatcher logs when an AI site is opened in or closed from Chrome.
type browserWatcher struct {
	logger *slog.Logger
	rec    recorder
	open   map[string]bool
}

func newBrowserWatcher(logger *slog.Logger) *browserWatcher {
	return &browserWatcher{logger: logger, rec: nopRecorder{}, open: map[string]bool{}}
}

func (w *browserWatcher) scan(ctx context.Context, initial bool) error {
	hosts, err := chromeTabHosts(ctx)
	if err != nil {
		return err
	}

	now := map[string]bool{}
	for _, h := range hosts {
		now[h] = true
		if w.open[h] {
			continue
		}
		msg := "ai site opened"
		if initial {
			msg = "ai site open"
		}
		w.logger.Info(msg, "browser", "chrome", "site", h)
		w.rec.Record(metricEvent{Kind: kindAISiteOpened, App: h, Mode: initialMode(initial)})
	}

	closed := make([]string, 0)
	for h := range w.open {
		if !now[h] {
			closed = append(closed, h)
		}
	}
	slices.Sort(closed)
	for _, h := range closed {
		w.logger.Info("ai site closed", "browser", "chrome", "site", h)
		w.rec.Record(metricEvent{Kind: kindAISiteClosed, App: h})
	}

	w.open = now
	return nil
}
