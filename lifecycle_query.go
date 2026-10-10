package main

import (
	"database/sql"
	"slices"
	"time"
)

// The lifecycle fold, modeled on c11's journal reducer and query. Each agent
// session moves between phases as hook events arrive:
//
//	idle --turn_started--> working --question/plan_review/approval--> blocked
//	blocked --attention_resolved / approval answered--> working
//	working --turn_completed--> idle      any --agent_error--> error
//
// A session agent11 first sees mid-flight starts in "unknown". When agent11
// itself restarts or stops, every open interval ends (a crash ends them at the
// last recorded event and counts them as censored), because nothing was
// watching in between.

const defaultStallMs = 15 * 60 * 1000 // c11's default

type agentMetrics struct {
	Sessions struct {
		Started     int            `json:"started"`
		Seen        int            `json:"seen"` // sessions with any event in the window
		ByAgentKind map[string]int `json:"by_agent_kind"`
		ByModel     map[string]int `json:"by_model"`
	} `json:"sessions"`
	TimeInStateMs map[string]int64 `json:"time_in_state_ms"`
	BlockedMs     map[string]int64 `json:"blocked_ms"`
	Turns         struct {
		Started   int      `json:"started"`
		Completed int      `json:"completed"`
		Ambiguous int      `json:"ambiguous"` // a new turn began with no Stop for the last one, e.g. after an interrupt
		PerHour   *float64 `json:"per_hour"`
	} `json:"turns"`
	OperatorResponse struct {
		Status    string         `json:"status"`
		WaitCount int            `json:"wait_count"`
		WaitMs    int64          `json:"wait_ms"`
		WaitAvgMs *float64       `json:"wait_avg_ms"`
		WaitP50Ms *int64         `json:"wait_p50_ms"`
		WaitP95Ms *int64         `json:"wait_p95_ms"`
		Censored  int            `json:"censored_count"`
		ResumeMs  *int64         `json:"resume_ms"` // not observable without keystrokes; always null
		ByReason  map[string]int `json:"wait_count_by_reason"`
	} `json:"operator_response"`
	Errors struct {
		SessionFailure int `json:"session_failure"`
		ChildSpawned   int `json:"child_spawned"`
		ChildCompleted int `json:"child_completed"`
	} `json:"errors"`
	Stalls          []stall `json:"stalls"`
	StallsTruncated bool    `json:"stalls_truncated"`
	Censored        int     `json:"censored_intervals"`
}

type stall struct {
	SessionID   string `json:"session_id"`
	StartMs     int64  `json:"start_ms"`
	DurationMs  int64  `json:"duration_ms"`
	ThresholdMs int64  `json:"threshold_ms"`
	Ongoing     bool   `json:"ongoing"`
}

const maxStalls = 128

type sessionState struct {
	phase        string
	since        int64
	reason       string // why blocked
	request      string // the blocking request's tool_use_id, when known
	lastEvidence int64
	blockedSince int64
	agentKind    string
	model        string
}

func blockReason(kind string) string {
	switch kind {
	case kindQuestionRequested:
		return "question"
	case kindPlanReviewRequest:
		return "plan_review"
	}
	return "approval"
}

func queryAgents(db *sql.DB, f metricsFilters, stallMs int64, now time.Time, r *metricsReport) error {
	a := &r.Agents
	a.Sessions.ByAgentKind, a.Sessions.ByModel = map[string]int{}, map[string]int{}
	a.TimeInStateMs = map[string]int64{"working": 0, "blocked": 0, "idle": 0, "error": 0, "unknown": 0}
	a.BlockedMs = map[string]int64{"approval": 0, "question": 0, "plan_review": 0}
	a.OperatorResponse.ByReason = map[string]int{}
	a.Stalls = []stall{}

	// Every event is read, not just lifecycle rows: after a crash, open
	// intervals end at agent11's last sign of life of any kind.
	rows, err := db.Query(`SELECT at_ms, kind, COALESCE(session_id, ''), COALESCE(agent_kind, ''), COALESCE(model, ''),
		COALESCE(request_id, '') FROM events WHERE at_ms < ? ORDER BY seq`, f.ToMs)
	if err != nil {
		return err
	}
	defer rows.Close()

	inWindow := func(t int64) bool { return t >= f.FromMs && t < f.ToMs }
	overlap := func(from, to int64) int64 { return max(0, min(to, f.ToMs)-max(from, f.FromMs)) }
	sessions := map[string]*sessionState{}
	seen := map[string]bool{}
	var waits []int64
	var lastAt int64

	closeInterval := func(s *sessionState, end int64) {
		ov := overlap(s.since, end)
		a.TimeInStateMs[s.phase] += ov
		if s.phase == "blocked" {
			a.BlockedMs[s.reason] += ov
		}
		s.since = end
	}
	move := func(s *sessionState, phase string, at int64) {
		closeInterval(s, at) // uses the old phase and reason
		if phase != "blocked" {
			s.reason, s.request = "", ""
		}
		s.phase = phase
	}
	resolveWait := func(s *sessionState, at int64) {
		if s.blockedSince > 0 && inWindow(at) {
			w := at - s.blockedSince
			waits = append(waits, w)
			a.OperatorResponse.WaitMs += w
			a.OperatorResponse.ByReason[s.reason]++
		}
		s.blockedSince = 0 // reason stays until the blocked interval is closed
	}
	censorWait := func(s *sessionState, end int64) {
		if s.blockedSince > 0 && s.blockedSince < f.ToMs && end >= f.FromMs {
			a.OperatorResponse.Censored++
		}
		s.blockedSince = 0
	}
	addStall := func(id string, start, end int64, ongoing bool) {
		if overlap(start, end) <= 0 && !(ongoing && inWindow(end)) {
			return
		}
		if len(a.Stalls) >= maxStalls {
			a.StallsTruncated = true
			return
		}
		a.Stalls = append(a.Stalls, stall{SessionID: id, StartMs: start, DurationMs: end - start,
			ThresholdMs: stallMs, Ongoing: ongoing})
	}
	// evidence refreshes a working session, first recording a stall if the
	// gap since the last evidence passed the threshold.
	evidence := func(id string, s *sessionState, at int64) {
		if s.phase == "working" && s.lastEvidence > 0 && at-s.lastEvidence > stallMs {
			addStall(id, s.lastEvidence, at, false)
		}
		s.lastEvidence = at
	}
	endAll := func(end int64, censored bool) {
		for _, s := range sessions {
			closeInterval(s, end)
			if censored {
				a.Censored++
			}
			censorWait(s, end)
		}
		clear(sessions)
	}

	for rows.Next() {
		var at int64
		var kind, id, agentKind, model, request string
		if err := rows.Scan(&at, &kind, &id, &agentKind, &model, &request); err != nil {
			return err
		}
		switch kind {
		case kindAgentStarted:
			endAll(lastAt, true)
			lastAt = at
			continue
		case kindAgentStopped:
			endAll(at, false)
			lastAt = at
			continue
		}
		lastAt = at
		if !slices.Contains(lifecycleKinds, kind) {
			continue
		}
		if f.AgentKind != "" && agentKind != f.AgentKind {
			continue
		}
		s := sessions[id]
		if s == nil {
			s = &sessionState{phase: "unknown", since: at, agentKind: agentKind}
			if kind == kindSessionStarted {
				s.phase = "idle"
				if inWindow(at) {
					a.Sessions.Started++
				}
			}
			sessions[id] = s
		}
		if s.model == "" && model != "" {
			s.model = model
		}
		if s.agentKind == "" {
			s.agentKind = agentKind
		}
		if f.Model != "" && s.model != f.Model {
			continue
		}
		if inWindow(at) && !seen[id] {
			// Count the session by kind and model the first time it is seen in
			// the window, so agents without a session-start event still appear.
			seen[id] = true
			a.Sessions.ByAgentKind[s.agentKind]++
			if s.model != "" {
				a.Sessions.ByModel[s.model]++
			}
		}

		switch kind {
		case kindSessionEnded:
			closeInterval(s, at)
			censorWait(s, at)
			delete(sessions, id)
		case kindTurnStarted:
			if s.phase == "blocked" {
				resolveWait(s, at) // a new prompt answers whatever was pending
			}
			if inWindow(at) {
				a.Turns.Started++
				if s.phase == "working" {
					a.Turns.Ambiguous++
				}
			}
			move(s, "working", at)
			s.lastEvidence = at
		case kindQuestionRequested, kindPlanReviewRequest, kindApprovalRequested:
			reason := blockReason(kind)
			if s.phase == "blocked" && s.reason == reason && (request == "" || s.request == "" || request == s.request) {
				// Claude sends both Notification and PermissionRequest for one prompt.
				if s.request == "" {
					s.request = request
				}
				continue
			}
			if s.phase == "blocked" {
				resolveWait(s, at)
			}
			evidence(id, s, at)
			move(s, "blocked", at)
			s.reason, s.request, s.blockedSince = reason, request, at
		case kindAttentionResolved:
			if s.phase == "blocked" && (s.request == "" || request == s.request) {
				resolveWait(s, at)
				move(s, "working", at)
				s.lastEvidence = at
			}
		case kindToolActivity:
			switch s.phase {
			case "blocked":
				// A tool running after a permission prompt means it was answered.
				// A question or plan review is only answered by its own result.
				if s.reason == "approval" {
					resolveWait(s, at)
					move(s, "working", at)
					s.lastEvidence = at
				}
			case "unknown":
				move(s, "working", at)
				s.lastEvidence = at
			case "working":
				evidence(id, s, at)
			}
		case kindTurnCompleted:
			if s.phase == "blocked" {
				if s.reason != "approval" {
					continue // Claude cannot stop with a question pending (c11's rule)
				}
				resolveWait(s, at)
			}
			if inWindow(at) {
				a.Turns.Completed++
			}
			evidence(id, s, at)
			move(s, "idle", at)
		case kindAgentError:
			if inWindow(at) {
				a.Errors.SessionFailure++
			}
			censorWait(s, at)
			move(s, "error", at)
		case kindChildSpawned:
			if inWindow(at) {
				a.Errors.ChildSpawned++
			}
			evidence(id, s, at)
		case kindChildCompleted:
			if inWindow(at) {
				a.Errors.ChildCompleted++
			}
			evidence(id, s, at)
		case kindAgentObservation:
			if s.phase == "working" {
				evidence(id, s, at)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	end := min(f.ToMs, now.UnixMilli())
	ids := make([]string, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		s := sessions[id]
		closeInterval(s, end)
		censorWait(s, end)
		if s.phase == "working" && s.lastEvidence > 0 && end-s.lastEvidence > stallMs {
			addStall(id, s.lastEvidence, end, true)
		}
	}

	a.Sessions.Seen = len(seen)
	o := &a.OperatorResponse
	o.WaitCount = len(waits)
	o.Status = "unavailable"
	if len(waits) > 0 {
		o.Status = "available"
		avg := round2(float64(o.WaitMs) / float64(len(waits)))
		o.WaitAvgMs = &avg
		slices.Sort(waits)
		p50, p95 := waits[max((len(waits)*50+99)/100-1, 0)], waits[max((len(waits)*95+99)/100-1, 0)]
		o.WaitP50Ms, o.WaitP95Ms = &p50, &p95
	}
	if r.Coverage.CoveredHours > 0 {
		v := round2(float64(a.Turns.Started) / r.Coverage.CoveredHours)
		a.Turns.PerHour = &v
	}
	return nil
}

type launchMetrics struct {
	SessionsByAgentKind map[string]int `json:"sessions_by_agent_kind"`
	SessionsByModel     map[string]int `json:"sessions_by_model"`
	AppStarts           map[string]int `json:"app_starts"` // AI apps launched while agent11 watched
	RequestsByModel     map[string]int `json:"requests_by_model"`
	RequestsByProvider  map[string]int `json:"requests_by_provider"`
}

func queryLaunches(db *sql.DB, f metricsFilters, r *metricsReport) error {
	l := &r.Launches
	l.SessionsByAgentKind, l.SessionsByModel = r.Agents.Sessions.ByAgentKind, r.Agents.Sessions.ByModel
	l.AppStarts, l.RequestsByModel, l.RequestsByProvider = map[string]int{}, map[string]int{}, map[string]int{}
	// Apps already running when agent11 started are marked "initial" and are
	// not launches.
	if err := groupCount(db, `SELECT app, COUNT(*) FROM events WHERE kind = ? AND COALESCE(mode, '') != 'initial'
		AND at_ms >= ? AND at_ms < ? GROUP BY app`, []any{kindAIAppStarted, f.FromMs, f.ToMs}, l.AppStarts); err != nil {
		return err
	}
	where, args := decisionWhere(f)
	if err := groupCount(db, `SELECT COALESCE(e.model, '(none)'), COUNT(*) FROM events e WHERE `+where+` GROUP BY 1`, args, l.RequestsByModel); err != nil {
		return err
	}
	return groupCount(db, `SELECT COALESCE(e.provider, '(none)'), COUNT(*) FROM events e WHERE `+where+` GROUP BY 1`, args, l.RequestsByProvider)
}

type resourceUsage struct {
	Samples   int     `json:"samples"` // one per app per minute of watching
	CPUAvg    float64 `json:"cpu_avg_pct"`
	CPUPeak   float64 `json:"cpu_peak_pct"`
	RSSAvgMB  float64 `json:"rss_avg_mb"`
	RSSPeakMB float64 `json:"rss_peak_mb"`
	ProcsPeak int     `json:"procs_peak"`
}

func queryResources(db *sql.DB, f metricsFilters, r *metricsReport) error {
	r.Resources = map[string]resourceUsage{}
	rows, err := db.Query(`SELECT app, COUNT(*), AVG(cpu_pct), MAX(cpu_max), AVG(rss_kb), MAX(rss_kb), MAX(procs)
		FROM events WHERE kind = ? AND at_ms >= ? AND at_ms < ? GROUP BY app`, kindResource, f.FromMs, f.ToMs)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var app string
		var u resourceUsage
		var rssAvg float64
		var rssPeak int64
		if err := rows.Scan(&app, &u.Samples, &u.CPUAvg, &u.CPUPeak, &rssAvg, &rssPeak, &u.ProcsPeak); err != nil {
			return err
		}
		u.CPUAvg, u.CPUPeak = round2(u.CPUAvg), round2(u.CPUPeak)
		u.RSSAvgMB, u.RSSPeakMB = round2(rssAvg/1024), round2(float64(rssPeak)/1024)
		r.Resources[app] = u
	}
	return rows.Err()
}
