# CLAUDE.md

agent11 is a single-binary Go monitor that watches the system clipboard, running AI/LLM apps, and AI sites open in Chrome, and appends each change to a rotating logfmt log. Captured text is scanned for secrets and PII (DLP) before it is logged. An optional loopback HTTP endpoint lets other tools (a browser extension, a script) submit text for the same DLP scan.

The project is standard library only, with no third-party dependencies. Keep it that way unless asked.

## Build and run

```bash
go build -o agent11 .      # binary is gitignored
go vet ./...
gofmt -l .                 # must print nothing
./agent11 -once            # print current clipboard and exit
./agent11 -quiet -log-content=false -dlp-keywords=CONFIDENTIAL,ProjectX
./agent11 -listen 127.0.0.1:8787   # token printed to stderr
```

`go.mod` declares `go 1.27.1`; the code uses `min`, `slices`, and `log/slog`. There are no tests yet. New tests go in `*_test.go` beside the file under test and run with `go test ./...`.

## Layout

Everything is `package main` in the repo root.

| File | Responsibility |
|---|---|
| `main.go` | Flags, clipboard polling loop, `logClipboard`, wiring of the other watchers |
| `procwatch.go` | AI app detection from the process list (`aiApps`), grouping helpers under one app, command-line redaction |
| `browserwatch.go` | AI site detection in Chrome tabs via `osascript` (`aiSites`), macOS only |
| `dlp.go` | DLP rules (`builtinRules`), Luhn check, user keyword rules, `scan` and `summary` |
| `intake.go` | Optional `/scan` and `/healthz` HTTP endpoint with bearer-token auth |
| `rotate.go` | `rotatingFile`, a size and line-count rotating `io.Writer` |

## Platform behavior

Clipboard reads shell out to `pbpaste` (macOS), PowerShell `Get-Clipboard` (Windows), or `wl-paste`, `xclip`, `xsel` (Linux, first one found). Process listing uses `ps` on Unix and `tasklist` on Windows, where only image names are available, so command-line patterns never match there. Every external command runs under `readTimeout` (3s) so a hung helper cannot stall the loop.

## Invariants to preserve

These are deliberate privacy and safety choices. Do not weaken them without being asked.

- DLP `scan` returns rule names and counts only, never the matched text. Log `dlp=` summaries, not values.
- With `-log-content=false`, raw clipboard and intake text must never reach the log.
- The intake endpoint refuses non-loopback addresses (`isLoopback`), compares tokens with `subtle.ConstantTimeCompare`, caps bodies at `maxIntakeBytes`, and prints a generated token to stderr only, never to the log.
- Browser watching logs the host only, never the URL path or query.
- Process command lines go through `sanitizeCmd` (redacts key/token/secret args, truncates to 300 chars) before logging.
- Log files are created with mode `0600`.
- Repeated errors are logged once per distinct message (`lastErr` pattern), not on every tick.

## Extending

- New AI desktop or CLI app: add an `app(...)` entry to `aiApps` in `procwatch.go` using `macApp`, `exeName`, or `contains`. Order matters: the first match wins, so put specific bundle matches before broad executable names.
- New AI website: add the host suffix to `aiSites` in `browserwatch.go`.
- New DLP rule: add to `builtinRules` in `dlp.go`. Match on structure, not real values, and add a `validate` func when the pattern alone is noisy (see `luhnValid`).
- New flag: define it in `main()` alongside the others and include it in the `agent11 started` log line if it affects behavior.

## Conventions

- Comments explain why, at the density already in the files. Match it.
- Wrap errors with `fmt.Errorf("context: %w", err)`; join multiple with `errors.Join`.
- Log with `slog` key/value pairs, short lowercase messages (`"ai app started"`, `"clipboard read failed"`).
- Never commit `agent11` (the binary) or `*.log` files; logs can contain captured clipboard data.
