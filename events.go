package main

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// Event is one decision as sent to a sink. Like Decision, it carries labels
// and counts only, never request content, so the recorder can rebuild an
// incident timeline without becoming a store of what it protects.
type Event struct {
	Time time.Time
	Decision
}

// Sink receives decision events. The default writes logfmt to the rotating
// log; an HTTP sink for SwarmSentinel is planned for phase 2.
type Sink interface {
	Emit(Event) error
}

type logSink struct {
	logger *slog.Logger
}

func (s logSink) Emit(e Event) error {
	d := e.Decision
	msg := "request allowed"
	level := slog.LevelInfo
	switch {
	case d.enforced():
		msg, level = "request blocked", slog.LevelWarn
	case d.Verdict != VerdictAllow:
		msg, level = "request flagged", slog.LevelWarn // report mode: would have applied
	}
	attrs := []any{
		"ts", e.Time.UTC().Format(time.RFC3339Nano),
		"verdict", d.Verdict.String(),
		"applied", d.Applied.String(),
		"enforced", d.enforced(),
		"mode", d.Mode,
		"dest", d.Destination,
		"category", d.Category,
		"classifier", d.Classifier,
	}
	if len(d.Classes) > 0 {
		attrs = append(attrs, "classes", strings.Join(d.Classes, ","),
			"rules", strings.Join(d.Rules, ","), "confidence", d.Confidence)
	}
	if d.AgentID != "" {
		attrs = append(attrs, "agent_id", d.AgentID, "agent_id_source", d.AgentIDSource)
	}
	s.logger.Log(context.Background(), level, msg, attrs...)
	return nil
}
