package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// dlpRule flags a class of sensitive data by pattern. count, when set, does a
// second pass over each match and returns how many real hits it holds (e.g.
// card numbers that pass Luhn), to cut false positives; zero rejects it.
type dlpRule struct {
	name  string
	re    *regexp.Regexp
	count func(string) int
}

// hits returns how many times the rule fires in text.
func (r dlpRule) hits(text string) int {
	n := 0
	for _, m := range r.re.FindAllString(text, -1) {
		if r.count == nil {
			n++
		} else {
			n += r.count(m)
		}
	}
	return n
}

// builtinRules detect common secrets and PII. They match structure, not the
// secret's value, so nothing here needs a real credential to test.
var builtinRules = []dlpRule{
	{name: "private-key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{name: "aws-access-key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "gcp-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{name: "openai-key", re: regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`)},
	{name: "anthropic-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\bgh[opsu]_[A-Za-z0-9]{36,}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{name: "email", re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)},
	{name: "us-ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	// A run of digit groups split by single spaces, dashes, or dots. The run is
	// matched whole and searched for cards in cardsIn, because a greedy 13-19
	// digit match would swallow a trailing expiry or CVV and fail Luhn.
	{name: "credit-card", re: regexp.MustCompile(`\b\d+(?:[ .-]\d+)*\b`), count: cardsIn},
}

// cardsIn counts card numbers in a run of digit groups. A card is a window of
// whole consecutive groups holding 13 to 19 digits that starts with a card
// network digit (2 to 6) and passes Luhn. Windows start at every group, so a
// number stays visible when an order ID precedes it or an expiry and CVV
// follow it on the same line; a found card's groups are not reused.
func cardsIn(run string) int {
	groups := strings.FieldsFunc(run, func(r rune) bool { return r == ' ' || r == '-' || r == '.' })
	n := 0
	for i := 0; i < len(groups); {
		found := 0
		digits := 0
		for j := i; j < len(groups) && digits < 19; j++ {
			digits += len(groups[j])
			if digits >= 13 && digits <= 19 && groups[i][0] >= '2' && groups[i][0] <= '6' &&
				luhnValid(strings.Join(groups[i:j+1], "")) {
				found = j - i + 1
				break
			}
		}
		if found > 0 {
			n++
			i += found
		} else {
			i++
		}
	}
	return n
}

// luhnValid reports whether the digits in s pass the Luhn checksum, which
// every real card number does. It filters out arbitrary long digit strings.
func luhnValid(s string) bool {
	var sum, n int
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
		n++
	}
	return n >= 13 && sum%10 == 0
}

type finding struct {
	rule  string
	count int
}

// dlpScanner holds the active rule set: built-ins plus any user keywords.
type dlpScanner struct {
	rules []dlpRule
}

// newDLPScanner builds a scanner. Each keyword becomes a case-insensitive
// literal rule named "keyword:<word>", for internal markers like a project
// codename or "CONFIDENTIAL".
func newDLPScanner(keywords []string) *dlpScanner {
	rules := append([]dlpRule(nil), builtinRules...)
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		rules = append(rules, dlpRule{
			name: "keyword:" + kw,
			re:   regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw)),
		})
	}
	return &dlpScanner{rules: rules}
}

// scan returns one finding per rule that matched, with a count. It never
// returns the matched text, so callers can log findings without re-recording
// the sensitive value.
func (s *dlpScanner) scan(text string) []finding {
	var out []finding
	for _, r := range s.rules {
		if n := r.hits(text); n > 0 {
			out = append(out, finding{rule: r.name, count: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rule < out[j].rule })
	return out
}

// summary renders findings as "rule:count,rule:count" for a log field.
func summary(fs []finding) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = fmt.Sprintf("%s:%d", f.rule, f.count)
	}
	return strings.Join(parts, ",")
}
