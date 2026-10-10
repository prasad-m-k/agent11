package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"slices"
	"strings"
)

// The clipboard guard replaces a sensitive clipboard with a notice, so a paste
// into an AI chat carries nothing. It is a stopgap until a browser extension
// can block the submit itself, and it has a race: a paste inside one polling
// interval of the copy still goes through. It changes the user's clipboard,
// so it is off unless -clipboard-guard asks for it.

const (
	guardOff    = "off"
	guardAI     = "ai"     // only while an AI site is open in Chrome or a desktop AI app runs
	guardAlways = "always" // on every sensitive copy
)

// defaultGuardRules are the findings worth wiping a clipboard for. Email is
// left out: copying an address is routine and wiping it would be noise.
const defaultGuardRules = "credit-card,us-ssn,private-key,aws-access-key,gcp-api-key," +
	"openai-key,anthropic-key,github-token,slack-token,jwt,keyword:*"

type clipboardGuard struct {
	mode        string
	rules       map[string]bool
	allKeywords bool // "keyword:*": every -dlp-keywords marker
}

func newClipboardGuard(mode, rules string) (*clipboardGuard, error) {
	if mode != guardOff && mode != guardAI && mode != guardAlways {
		return nil, fmt.Errorf("-clipboard-guard %q is not off, ai, or always", mode)
	}
	g := &clipboardGuard{mode: mode, rules: map[string]bool{}}
	for _, r := range splitList(rules) {
		switch {
		case r == "keyword:*":
			g.allKeywords = true
		case strings.HasPrefix(r, "keyword:"):
			g.rules[r] = true
		default:
			if _, ok := builtinRuleByName[r]; !ok {
				return nil, fmt.Errorf("-guard-rules: %q is not a built-in rule name or keyword:<word>", r)
			}
			g.rules[r] = true
		}
	}
	return g, nil
}

// trigger returns the findings that should make the guard act: none when the
// guard is off, or in ai mode with no AI context.
func (g *clipboardGuard) trigger(findings []finding, aiContext bool) []finding {
	if g.mode == guardOff || (g.mode == guardAI && !aiContext) {
		return nil
	}
	var out []finding
	for _, f := range findings {
		if g.rules[f.rule] || (g.allKeywords && strings.HasPrefix(f.rule, "keyword:")) {
			out = append(out, f)
		}
	}
	return out
}

// guardNotice is what the clipboard holds after the guard acts. It names the
// rules that fired and nothing of what was copied.
func guardNotice(fs []finding) string {
	return fmt.Sprintf("[agent11 cleared the clipboard: it held %s. Sensitive data must not be pasted into AI tools. "+
		"If this is wrong, contact security for an exception.]", summary(fs))
}

// desktopAIApps are the aiApps entries that are windows a person pastes into,
// as opposed to CLI tools or background servers.
var desktopAIApps = []string{"Claude Desktop", "Claude in Chrome", "ChatGPT", "Perplexity",
	"Cursor", "Windsurf", "LM Studio", "Jan", "Msty", "GPT4All"}

// clipboardWriteCommands mirrors clipboardCommands for writing; each reads
// the new contents from stdin.
func clipboardWriteCommands() [][]string {
	switch runtime.GOOS {
	case "darwin":
		return [][]string{{"pbcopy"}}
	case "windows":
		return [][]string{{"powershell", "-NoProfile", "-Command", "Set-Clipboard -Value ([Console]::In.ReadToEnd())"}}
	default:
		return [][]string{
			{"wl-copy"},
			{"xclip", "-selection", "clipboard", "-i"},
			{"xsel", "--clipboard", "--input"},
		}
	}
}

func writeClipboard(ctx context.Context, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	var errs []error
	for _, args := range clipboardWriteCommands() {
		if _, err := exec.LookPath(args[0]); err != nil {
			errs = append(errs, err)
			continue
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = bytes.NewReader(data)
		if err := cmd.Run(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", args[0], err))
			continue
		}
		return nil
	}
	return fmt.Errorf("no usable clipboard writer: %w", errors.Join(errs...))
}

// anyOpen reports whether the last scan saw an AI site open.
func (w *browserWatcher) anyOpen() bool { return len(w.open) > 0 }

// anyDesktop reports whether the last scan saw a desktop AI app running.
func (w *aiWatcher) anyDesktop() bool {
	for name := range w.running {
		if slices.Contains(desktopAIApps, name) {
			return true
		}
	}
	return false
}
