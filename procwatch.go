package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// aiApp identifies an AI/LLM application by patterns matched against a
// process's identity (see identity). The first matching app wins, so app
// bundles are listed before bare executable names that could also match them.
type aiApp struct {
	name string
	re   *regexp.Regexp
}

// exeName matches an executable by base name, e.g. /usr/bin/ollama or ollama.exe.
func exeName(n string) string {
	return `(^|[/\\])` + regexp.QuoteMeta(n) + `(\.exe)?$`
}

// macApp matches anything running from inside a macOS app bundle.
func macApp(n string) string {
	return `[/\\]` + regexp.QuoteMeta(n) + `\.app([/\\]|$)`
}

// contains matches a literal fragment anywhere in an identity string.
func contains(s string) string { return regexp.QuoteMeta(s) }

func app(name string, patterns ...string) aiApp {
	return aiApp{name: name, re: regexp.MustCompile(`(?i)` + strings.Join(patterns, "|"))}
}

var aiApps = []aiApp{
	// Chrome launches this helper from Claude.app even when the desktop app is closed.
	app("Claude in Chrome", contains("Claude.app/Contents/Helpers/chrome-native-host")),
	app("Claude Desktop", macApp("Claude")),
	app("ChatGPT", macApp("ChatGPT"), exeName("ChatGPT")),
	app("Perplexity", macApp("Perplexity")),
	app("Cursor", macApp("Cursor"), exeName("Cursor"), exeName("cursor-agent")),
	app("Windsurf", macApp("Windsurf"), exeName("Windsurf")),
	app("LM Studio", macApp("LM Studio"), exeName("LM Studio"), exeName("lms"), contains(".lmstudio/")),
	app("Ollama", macApp("Ollama"), exeName("ollama"), exeName("ollama app")),
	app("Jan", macApp("Jan")),
	app("Msty", macApp("Msty"), exeName("Msty")),
	app("GPT4All", contains("gpt4all")),
	app("Claude Code", exeName("claude"), contains("@anthropic-ai/claude-code")),
	app("OpenAI Codex CLI", exeName("codex"), contains("@openai/codex")),
	app("Gemini CLI", exeName("gemini"), contains("@google/gemini-cli")),
	app("GitHub Copilot", contains("copilot-language-server"), contains("github.copilot"), exeName("copilot")),
	app("Aider", exeName("aider")),
	app("Codeium", contains("codeium")),
	app("Tabnine", contains("tabnine")),
	app("llama.cpp", exeName("llama-server"), exeName("llama-cli")),
	app("vLLM", exeName("vllm")),
	app("LocalAI", exeName("local-ai")),
	app("KoboldCpp", contains("koboldcpp")),
	app("Open WebUI", exeName("open-webui")),
	app("text-generation-webui", contains("text-generation-webui")),
	app("ComfyUI", contains("comfyui")),
}

// interpreters run the real program as a script argument, so for these the
// next few arguments are checked too (node .../claude, python -m aider).
var interpreters = regexp.MustCompile(`(?i)(^|[/\\])(node|bun|deno|npx|python[\d.]*|uv|uvx|pipx|ruby)(\.exe)?$`)

// identity returns the strings a process is matched on: its executable path
// and argv[0], plus the script arguments when argv[0] is an interpreter. The
// rest of the command line is ignored, so a shell or editor that merely
// mentions "ollama" in its arguments is not reported.
func identity(p process) []string {
	ids := []string{p.exe}
	args := strings.Fields(p.cmd)
	if len(args) == 0 {
		return ids
	}
	ids = append(ids, args[0])
	if interpreters.MatchString(args[0]) || interpreters.MatchString(p.exe) {
		ids = append(ids, args[1:min(len(args), 4)]...)
	}
	return ids
}

func matchAIApp(p process) (string, bool) {
	ids := identity(p)
	for _, a := range aiApps {
		for _, id := range ids {
			if id != "" && a.re.MatchString(id) {
				return a.name, true
			}
		}
	}
	return "", false
}

type process struct {
	pid, ppid int
	exe       string // executable path (macOS) or short name (Linux, Windows)
	cmd       string // full command line, empty on Windows
}

// listProcesses returns every process with its command line. Windows only
// exposes image names through tasklist, so matching there is by exe name.
func listProcesses(ctx context.Context) ([]process, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	if runtime.GOOS == "windows" {
		out, err := exec.CommandContext(ctx, "tasklist", "/fo", "csv", "/nh").Output()
		if err != nil {
			return nil, fmt.Errorf("tasklist: %w", err)
		}
		records, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
		if err != nil {
			return nil, fmt.Errorf("tasklist: %w", err)
		}
		var procs []process
		for _, r := range records {
			if len(r) < 2 {
				continue
			}
			if pid, err := strconv.Atoi(r[1]); err == nil {
				procs = append(procs, process{pid: pid, exe: r[0]})
			}
		}
		return procs, nil
	}

	// comm and args both may contain spaces, so each needs to be the last
	// column; take them in two calls and join on pid.
	out, err := exec.CommandContext(ctx, "ps", "-A", "-o", "pid=,ppid=,comm=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	var procs []process
	byPID := map[int]int{}
	for _, line := range strings.Split(string(out), "\n") {
		pidStr, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
		ppidStr, comm, _ := strings.Cut(strings.TrimSpace(rest), " ")
		pid, err1 := strconv.Atoi(pidStr)
		ppid, err2 := strconv.Atoi(ppidStr)
		if err1 != nil || err2 != nil {
			continue
		}
		byPID[pid] = len(procs)
		procs = append(procs, process{pid: pid, ppid: ppid, exe: strings.TrimSpace(comm)})
	}

	out, err = exec.CommandContext(ctx, "ps", "-A", "-ww", "-o", "pid=,args=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		pidStr, args, _ := strings.Cut(strings.TrimSpace(line), " ")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		if i, ok := byPID[pid]; ok {
			procs[i].cmd = strings.TrimSpace(args)
		}
	}
	return procs, nil
}

var secretArg = regexp.MustCompile(`(?i)(--?[\w-]*(?:key|token|secret|password|passwd)[\w-]*[= ])\S+|\b(sk-|sk-ant-|ghp_|xox[bp]-)[\w-]{8,}`)

// sanitizeCmd hides likely credentials in a command line and caps its length
// before it goes into the log.
func sanitizeCmd(cmd string) string {
	cmd = secretArg.ReplaceAllStringFunc(cmd, func(m string) string {
		sub := secretArg.FindStringSubmatch(m)
		if sub[1] != "" {
			return sub[1] + "[REDACTED]"
		}
		return sub[2] + "[REDACTED]"
	})
	const maxLen = 300
	if len(cmd) > maxLen {
		cmd = cmd[:maxLen] + "..."
	}
	return cmd
}

// aiWatcher logs when AI apps appear or disappear. An app's helper processes
// are grouped under it, so an Electron app with a dozen helpers is one entry.
type aiWatcher struct {
	logger  *slog.Logger
	running map[string]bool
	self    int
}

func newAIWatcher(logger *slog.Logger) *aiWatcher {
	return &aiWatcher{logger: logger, running: map[string]bool{}, self: os.Getpid()}
}

func (w *aiWatcher) scan(ctx context.Context, initial bool) error {
	procs, err := listProcesses(ctx)
	if err != nil {
		return err
	}

	groups := map[string][]process{}
	for _, p := range procs {
		if p.pid == w.self {
			continue
		}
		if name, ok := matchAIApp(p); ok {
			groups[name] = append(groups[name], p)
		}
	}

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if w.running[name] {
			continue
		}
		main := mainProcess(groups[name])
		msg := "ai app started"
		if initial {
			msg = "ai app running"
		}
		cmd := main.cmd
		if cmd == "" {
			cmd = main.exe
		}
		w.logger.Info(msg, "app", name, "pid", main.pid, "procs", len(groups[name]), "cmd", sanitizeCmd(cmd))
	}

	stopped := make([]string, 0)
	for name := range w.running {
		if _, ok := groups[name]; !ok {
			stopped = append(stopped, name)
		}
	}
	slices.Sort(stopped)
	for _, name := range stopped {
		w.logger.Info("ai app stopped", "app", name)
	}

	w.running = map[string]bool{}
	for name := range groups {
		w.running[name] = true
	}
	return nil
}

// mainProcess picks the process in a group whose parent is outside the
// group, i.e. the app itself rather than one of its helpers.
func mainProcess(group []process) process {
	pids := map[int]bool{}
	for _, p := range group {
		pids[p.pid] = true
	}
	best := group[0]
	for _, p := range group {
		isRoot, bestIsRoot := !pids[p.ppid], !pids[best.ppid]
		if (isRoot && !bestIsRoot) || (isRoot == bestIsRoot && p.pid < best.pid) {
			best = p
		}
	}
	return best
}
