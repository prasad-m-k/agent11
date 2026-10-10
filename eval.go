package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// The -eval mode scores the pipeline against a labeled corpus. The corpus
// directory holds one file per class and label, named <class>.positive.txt or
// <class>.negative.txt, with samples separated by a line containing only
// "---". normal.negative.txt holds ordinary traffic that no class should
// match; it counts as a negative for every class.

const (
	evalSeparator = "---"
	evalNormal    = "normal"
)

type evalSample struct {
	class    string // class ID, or evalNormal
	positive bool
	text     string
}

func loadCorpus(dir string) ([]evalSample, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	var out []evalSample
	for _, f := range files {
		base := strings.TrimSuffix(filepath.Base(f), ".txt")
		class, label, ok := strings.Cut(base, ".")
		if !ok || (label != "positive" && label != "negative") {
			return nil, fmt.Errorf("corpus file %s: name must be <class>.positive.txt or <class>.negative.txt", f)
		}
		if class == evalNormal && label == "positive" {
			return nil, fmt.Errorf("corpus file %s: %s samples can only be negative", f, evalNormal)
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, s := range splitSamples(string(data)) {
			out = append(out, evalSample{class: class, positive: label == "positive", text: s})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("corpus %s has no samples", dir)
	}
	return out, nil
}

func splitSamples(data string) []string {
	var out []string
	var cur []string
	flush := func() {
		if s := strings.TrimSpace(strings.Join(cur, "\n")); s != "" {
			out = append(out, s)
		}
		cur = cur[:0]
	}
	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) == evalSeparator {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return out
}

type evalCounts struct {
	positives, misses        int
	negatives, falsePositive int
}

// runEval decides every sample against an unlisted destination (each class's
// strictest action) and reports, per class, how often a positive was missed
// and how often a negative was matched, plus latency percentiles.
func runEval(ctx context.Context, d *decider, samples []evalSample, w io.Writer) error {
	p := d.policy.Load()
	known := map[string]bool{}
	for _, c := range p.Classes {
		known[c.ID] = true
	}
	counts := map[string]*evalCounts{}
	for _, c := range p.Classes {
		counts[c.ID] = &evalCounts{}
	}
	for _, s := range samples {
		if s.class != evalNormal && !known[s.class] {
			return fmt.Errorf("corpus class %q is not in the policy", s.class)
		}
	}

	var latencies []time.Duration
	for _, s := range samples {
		start := time.Now()
		dec := d.decide(ctx, decideRequest{Text: s.text, Destination: ""})
		latencies = append(latencies, time.Since(start))
		matched := map[string]bool{}
		for _, c := range dec.Classes {
			matched[c] = true
		}
		for id, c := range counts {
			switch {
			case s.class == id && s.positive:
				c.positives++
				if !matched[id] {
					c.misses++
				}
			case s.class == id || s.class == evalNormal:
				c.negatives++
				if matched[id] {
					c.falsePositive++
				}
			}
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "class\tpositives\tmisses\tmiss_rate\tnegatives\tfalse_pos\tfp_rate")
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		c := counts[id]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%d\t%d\t%s\n", id, c.positives, c.misses, rate(c.misses, c.positives),
			c.negatives, c.falsePositive, rate(c.falsePositive, c.negatives))
	}
	tw.Flush()

	slices.Sort(latencies)
	fmt.Fprintf(w, "\nsamples=%d classifier=%s latency p50=%s p95=%s p99=%s\n", len(samples), d.classifier.Name(),
		percentile(latencies, 50), percentile(latencies, 95), percentile(latencies, 99))
	return nil
}

func rate(n, of int) string {
	if of == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(of))
}

// percentile expects sorted input and uses the nearest-rank method.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := (len(sorted)*p + 99) / 100
	return sorted[max(i-1, 0)].Round(time.Microsecond)
}
