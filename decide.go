package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// decideRequest is what the pipeline looks at. Text never leaves the
// pipeline: only the Decision does.
type decideRequest struct {
	Text        string
	Labels      []string // source labels from a launcher; a hint, see AgentIDSource
	AgentID     string
	Destination string // upstream host
}

// Decision is the pipeline's output and the payload of every event. It must
// never carry request content, matched text, or prompts.
type Decision struct {
	Verdict       Verdict // strictest verdict across matched classes, enforced or not
	Applied       Verdict // what the proxy acts on: the strictest verdict among enforce-mode classes
	Classes       []string
	Rules         []string // detector names that fired, e.g. "label:repo:x", "rule:aws-access-key"
	Confidence    float64  // 1 for deterministic hits, the classifier probability otherwise
	Mode          string   // enforce if any matched class enforces, else report
	AgentID       string
	AgentIDSource string
	Destination   string
	Category      string // destination category, or "unlisted"
	Classifier    string // not-needed, disabled, used, or unavailable
	Owners        []string
}

func (d Decision) enforced() bool { return d.Applied != VerdictAllow }

const categoryUnlisted = "unlisted"

// decider holds the live policy and the classifier. The policy pointer is
// swapped on reload, so a request always sees one consistent policy.
type decider struct {
	policy     atomic.Pointer[Policy]
	classifier Classifier
	timeout    time.Duration
	modeFlag   string // overrides the policy's global mode when set

	// exhaustive asks the classifier about every enabled class even when a
	// deterministic hit already settles the verdict. Eval uses it so each class
	// is scored on its own.
	exhaustive bool
}

func newDecider(p *Policy, c Classifier, timeout time.Duration, modeFlag string) *decider {
	if c == nil {
		c = noopClassifier{}
	}
	d := &decider{classifier: c, timeout: timeout, modeFlag: modeFlag}
	d.policy.Store(p)
	return d
}

func (d *decider) modeFor(p *Policy, c *Class) string {
	if c != nil && c.Mode != "" {
		return c.Mode
	}
	if d.modeFlag != "" {
		return d.modeFlag
	}
	return p.Mode
}

// classHit records why a class matched.
type classHit struct {
	class      *Class
	rules      []string
	confidence float64
	verdict    Verdict
}

// decide runs the pipeline: source labels and path globs, fingerprints, then
// patterns and keywords, all deterministic; the classifier only scores classes
// those steps left undecided, and only when its answer could change the result.
func (d *decider) decide(ctx context.Context, req decideRequest) Decision {
	p := d.policy.Load()
	cat, ok := p.category(req.Destination)
	if !ok {
		cat = categoryUnlisted
	}
	out := Decision{
		AgentID:     req.AgentID,
		Destination: req.Destination,
		Category:    cat,
		Classifier:  "not-needed",
		Confidence:  1,
	}
	if req.AgentID != "" {
		out.AgentIDSource = "declared" // no trusted launcher yet
	}

	paths := extractPaths(req.Text)
	prints := fingerprintsOf(req.Text)
	var hits []classHit
	hard := map[string]bool{}
	for _, c := range p.Classes {
		if rules := hardHits(c, req, paths, prints); len(rules) > 0 {
			hits = append(hits, classHit{class: c, rules: rules, confidence: 1, verdict: c.action(cat)})
			hard[c.ID] = true
		}
	}

	strictest := VerdictAllow
	for _, h := range hits {
		strictest = max(strictest, h.verdict)
	}

	// Ask the classifier only about classes it could still move to a stricter
	// verdict. If a hard hit already blocks, nothing is left to decide.
	var ask []*Class
	if d.exhaustive || strictest < VerdictBlock {
		for _, c := range p.Classes {
			if !c.Classifier.Enabled || hard[c.ID] {
				continue
			}
			if !d.exhaustive && c.action(cat) <= strictest {
				continue
			}
			ask = append(ask, c)
		}
	}
	if len(ask) > 0 {
		if _, isNoop := d.classifier.(noopClassifier); isNoop {
			out.Classifier = "disabled"
		} else {
			hits = append(hits, d.classify(ctx, req, paths, hits, ask, cat, &out)...)
		}
	}

	out.Mode = modeReport
	for _, h := range hits {
		out.Classes = append(out.Classes, h.class.ID)
		out.Rules = append(out.Rules, h.rules...)
		out.Confidence = min(out.Confidence, h.confidence)
		out.Verdict = max(out.Verdict, h.verdict)
		if d.modeFor(p, h.class) == modeEnforce {
			out.Mode = modeEnforce
			out.Applied = max(out.Applied, h.verdict)
		}
		if h.verdict != VerdictAllow && !slices.Contains(out.Owners, h.class.Owner) {
			out.Owners = append(out.Owners, h.class.Owner)
		}
	}
	if len(out.Classes) == 0 {
		out.Confidence = 0
	}
	slices.Sort(out.Rules)
	out.Rules = slices.Compact(out.Rules)
	return out
}

// classify runs the classifier with a bounded timeout. On failure it falls
// back to the deterministic result, except that labeled-but-unmatched input
// is blocked: a launcher said it came from somewhere sensitive and nothing
// could confirm otherwise.
func (d *decider) classify(ctx context.Context, req decideRequest, paths []string, hard []classHit, ask []*Class, cat string, out *Decision) []classHit {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	in := ClassifierInput{Features: features(req, paths, hard)}
	for _, c := range ask {
		if c.Classifier.Raw {
			in.Raw = req.Text // opted in per class in the policy, and logged at startup
			break
		}
	}
	probs, err := d.classifier.Classify(ctx, in, ask)
	if err != nil {
		out.Classifier = "unavailable"
		if len(req.Labels) == 0 {
			return nil
		}
		// Not tied to a class: apply under the global mode.
		p := d.policy.Load()
		fallback := &Class{ID: "labeled-unclassified", Owner: "security", Mode: d.modeFor(p, nil)}
		return []classHit{{class: fallback, rules: []string{"classifier-unavailable"}, confidence: 1, verdict: VerdictBlock}}
	}
	out.Classifier = "used"

	var hits []classHit
	for _, c := range ask {
		prob, ok := probs[c.ID]
		if !ok {
			continue
		}
		action := c.action(cat)
		var v Verdict
		switch {
		case prob >= c.Classifier.BlockAt:
			v = action
		case c.Classifier.HoldAt > 0 && prob >= c.Classifier.HoldAt:
			v = min(action, VerdictHold)
		default:
			continue
		}
		hits = append(hits, classHit{class: c, rules: []string{"classifier"}, confidence: prob, verdict: v})
	}
	return hits
}

// hardHits returns the deterministic detector names that matched class c.
func hardHits(c *Class, req decideRequest, paths []string, prints map[string]bool) []string {
	var rules []string
	for _, l := range req.Labels {
		if c.labels[l] {
			rules = append(rules, "label:"+l)
		}
	}
	for _, re := range c.globs {
		if slices.ContainsFunc(paths, re.MatchString) {
			rules = append(rules, "path-glob")
			break
		}
	}
	for fp := range prints {
		if c.prints[fp] {
			rules = append(rules, "fingerprint")
			break
		}
	}
	if c.keywords != nil && c.keywords.MatchString(req.Text) {
		rules = append(rules, "keyword")
	}
	for _, r := range c.rules {
		for _, m := range r.re.FindAllString(req.Text, -1) {
			if r.validate == nil || r.validate(m) {
				rules = append(rules, "rule:"+r.name)
				break
			}
		}
	}
	return rules
}

var pathToken = regexp.MustCompile(`(?:[A-Za-z]:)?[\w.~@+-]*(?:[/\\][\w.@+-]+)+[/\\]?`)

// extractPaths finds path-like tokens in text, normalized to forward slashes.
func extractPaths(text string) []string {
	ms := pathToken.FindAllString(text, -1)
	for i, m := range ms {
		ms[i] = strings.ReplaceAll(m, `\`, "/")
	}
	return ms
}

// fingerprintsOf hashes the whole text and each trimmed line of at least
// minFingerprintLen bytes, so a known document matches whether it is pasted
// whole or a distinctive line is quoted.
const minFingerprintLen = 20

func fingerprintsOf(text string) map[string]bool {
	out := map[string]bool{}
	add := func(s string) {
		sum := sha256.Sum256([]byte(s))
		out[hex.EncodeToString(sum[:])] = true
	}
	if t := strings.TrimSpace(text); t != "" {
		add(t)
	}
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); len(line) >= minFingerprintLen {
			add(line)
		}
	}
	return out
}

// docMarkers are labels that documents carry in their own text. Their
// presence is a feature for the classifier; the surrounding text is not.
var docMarkers = []struct {
	name string
	re   *regexp.Regexp
}{
	{"confidential", regexp.MustCompile(`(?i)\bconfidential\b`)},
	{"internal-only", regexp.MustCompile(`(?i)\binternal (?:use )?only\b`)},
	{"do-not-distribute", regexp.MustCompile(`(?i)\bdo not (?:distribute|forward|share)\b`)},
	{"privileged", regexp.MustCompile(`(?i)\bprivileged\b`)},
	{"proprietary", regexp.MustCompile(`(?i)\bproprietary\b`)},
	{"copyright", regexp.MustCompile(`(?i)copyright\s+(?:\(c\)|©)?\s*\d{4}`)},
	{"draft", regexp.MustCompile(`(?i)\bdraft\b`)},
}

// features describes text without containing it: source labels, path
// directories, document markers, size and shape, and rule counts. This is
// what a hosted classifier receives unless a class opts in to raw content.
func features(req decideRequest, paths []string, hard []classHit) string {
	var b strings.Builder
	if len(req.Labels) > 0 {
		fmt.Fprintf(&b, "source_labels: %s\n", strings.Join(req.Labels, ", "))
	}
	dirs := map[string]bool{}
	for _, p := range paths {
		// Directory names only; file names can be content in themselves.
		if i := strings.LastIndexByte(p, '/'); i > 0 {
			for _, part := range strings.Split(p[:i], "/") {
				if part != "" && part != "." && part != ".." {
					dirs[part] = true
				}
			}
		}
	}
	if len(dirs) > 0 {
		names := make([]string, 0, len(dirs))
		for d := range dirs {
			names = append(names, d)
		}
		slices.Sort(names)
		if len(names) > 40 {
			names = names[:40]
		}
		fmt.Fprintf(&b, "path_directories: %s\n", strings.Join(names, ", "))
	}
	var marks []string
	for _, m := range docMarkers {
		if m.re.MatchString(req.Text) {
			marks = append(marks, m.name)
		}
	}
	if len(marks) > 0 {
		fmt.Fprintf(&b, "document_markers: %s\n", strings.Join(marks, ", "))
	}
	lines := strings.Count(req.Text, "\n") + 1
	fmt.Fprintf(&b, "length_chars: %d\nlength_lines: %d\n", len(req.Text), lines)
	fmt.Fprintf(&b, "code_like_line_ratio: %.2f\n", codeLikeRatio(req.Text))
	if fs := (&dlpScanner{rules: builtinRules}).scan(req.Text); len(fs) > 0 {
		fmt.Fprintf(&b, "pattern_counts: %s\n", summary(fs))
	}
	var hardRules []string
	for _, h := range hard {
		hardRules = append(hardRules, h.rules...)
	}
	if len(hardRules) > 0 {
		fmt.Fprintf(&b, "deterministic_hits: %s\n", strings.Join(hardRules, ", "))
	}
	return b.String()
}

// codeLikeRatio is the share of non-empty lines that end like source code.
func codeLikeRatio(text string) float64 {
	var n, code int
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n++
		switch line[len(line)-1] {
		case ';', '{', '}', ')', ':':
			code++
		}
	}
	if n == 0 {
		return 0
	}
	return float64(code) / float64(n)
}
