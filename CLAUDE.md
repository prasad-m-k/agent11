# CLAUDE.md

agent11 is a single-binary Go tool that stops company information from leaking to LLMs and AI services. It works with any agent or AI tool: coding agents, chat apps, browser chats, scripts, and multi-agent swarms.

The data it protects is whatever the company defines: source code, prompts, product plans, customer data, legal material, financials. Legal data is one example class, not a special case.

agent11 has two jobs:

1. **Sense.** Watch the clipboard, running AI apps, and AI sites open in Chrome. Scan text for sensitive data and log findings.
2. **Decide and enforce.** Sit on the request path to LLM APIs, classify what is being sent, and allow, translate, hold, or block it according to a company policy file. Send each decision to the SwarmSentinel policy engine and flight recorder.

Job 1 exists today. Job 2's phase 1 pieces (policy, decision pipeline, report/enforce proxy, classifier interface, file sink, eval) are built. Read "Status" before changing anything.

The project uses the standard library plus one approved dependency, `modernc.org/sqlite` (pure Go, no cgo) for the metrics store. Ask before adding any other.

## Status

| Area | State |
| --- | --- |
| Clipboard, process, and Chrome tab watching | Built |
| DLP scan (secrets, PII, user keywords) | Built |
| Clipboard guard (replace a sensitive clipboard with a notice) | Built, off by default (`-clipboard-guard`) |
| Loopback `/scan` and `/healthz` endpoint | Built, returns findings only |
| Rotating log | Built |
| Metrics store (local SQLite) and `agent11 metrics query/export/clear` | Built (phase 1); dashboard planned (phase 2) |
| Agent lifecycle metrics from Claude Code and Antigravity hooks (time in state, blocked time, turns, operator waits, errors, stalls), launch stats, CPU and memory per AI app | Built (phase 1.1) |
| Declarative hook adapters: add a new agent via a JSON file, no recompile | Built (phase 1.1) |
| Local web dashboard over the metrics database (`agent11 dashboard`) | Built (phase 2) |
| Policy file, classes, destination matrix | Built (`policy.go`, `policy.example.json`), reloaded on change |
| Decision pipeline | Built (`decide.go`) |
| LLM reverse proxy that can block | Built (`proxy.go`), report mode by default |
| Classifier interface (Jev behind it) | Built (`classify.go`); Jev client not yet calibrated against live traffic |
| Decision events | File sink built (`events.go`); HTTP sink to SwarmSentinel planned (phase 2) |
| `-eval` against a labeled corpus | Built (`eval.go`); seed corpus is far below the 200 samples per class the exit criteria need |
| Surrogate translation (DPTP) | Interface stub only |
| c11 integration (agent identity, sidebar) | Out of scope until phase 3 |

agent11 can block only requests that agents send through the proxy, and only for classes in enforce mode. For browser chats it can at most wipe a sensitive clipboard (`-clipboard-guard`); it cannot see or stop typed text or a paste made within one polling interval of the copy. It reads request bodies in memory to decide, and never stores or logs them. It reads the response only to pull out the token-usage counts (integers), never the response content. Browser watching sees only the host of a tab. Do not describe planned features as working in code comments, logs, or docs.

## Build and run

```
go build -o agent11 .      # binary is gitignored
go vet ./...
gofmt -l .                 # must print nothing
go test ./...
./agent11 -once            # print current clipboard and exit
./agent11 -quiet -log-content=false -dlp-keywords=CONFIDENTIAL,ProjectX
./agent11 -listen 127.0.0.1:8787   # token printed to stderr
```

`go.mod` declares `go 1.27.1`; the code uses `min`, `slices`, `maps`, and `log/slog`. Tests go in `*_test.go` beside the file under test.

Enforcement flags (all listed in the `agent11 started` log line):

```
-policy policy.json          # policy file, JSON; required by -proxy and -eval
-proxy 127.0.0.1:8788        # LLM reverse proxy, loopback only
-proxy-max-mb 32             # largest body the proxy scans and forwards
-mode report                 # overrides the policy's global mode; per-class mode still wins
-eval testdata/corpus        # per-class miss and false-positive rates, then exit
-classifier none             # none or jev (reads OPENROUTER_API_KEY)
-classifier-model typesafe/jev-1.13
-classifier-timeout 2s
-clipboard-guard off          # off, ai (AI site or desktop AI app open), or always
-guard-rules <list>           # DLP rules that trigger the guard; default: all but email, plus keyword:*
-metrics=true                 # body-free metrics in SQLite; -metrics-db, -metrics-retention 336h, -metrics-max-mb 256
```

Read the metrics store with or without agent11 running:

```
./agent11 metrics query --from 24h [--json] [--class id --dest host --category name --agent id]
                         [--agent-kind claude-code --model id --stall-ms 900000]
./agent11 metrics export --from 7d --output events.ndjson
./agent11 metrics clear --yes
./agent11 hook --list-agents                              # built-in + custom agents (adapters dir)
./agent11 hook --print-config [<agent>]                   # config fragment wiring that agent's lifecycle hooks to agent11
./agent11 dashboard [--db path] [--listen 127.0.0.1:9090]  # read-only web view of the metrics database
#   (the collector also serves it on 127.0.0.1:9090 by default; -dashboard "" turns it off)
```

`-hooks` (default true, needs `-metrics`) serves `agent11 hook` on `-hook-socket`, default `<user config dir>/agent11/hooks.sock`.

Point agents at the proxy with the upstream host as the first path segment:

```
ANTHROPIC_BASE_URL=http://127.0.0.1:8788/api.anthropic.com
OPENAI_BASE_URL=http://127.0.0.1:8788/api.openai.com/v1
```

Optional request headers, stripped before forwarding: `X-Agent11-Labels` (comma-separated source labels) and `X-Agent11-Agent` (declared agent ID).

## Layout

Everything is `package main` in the repo root unless a file says otherwise.

| File | Responsibility |
| --- | --- |
| `main.go` | Flags, clipboard polling loop, `logClipboard`, wiring of the other components |
| `procwatch.go` | AI app detection from the process list (`aiApps`), grouping helpers, command-line redaction |
| `browserwatch.go` | AI site detection in Chrome tabs via `osascript` (`aiSites`), macOS only |
| `dlp.go` | DLP rules (`builtinRules`), card search (`cardsIn`) and Luhn check, user keyword rules, `scan` and `summary` |
| `metrics.go` | Metrics store: schema, private file creation, batched writer, retention, `recorder` interface |
| `metrics_query.go` | `agent11 metrics` CLI: query report, NDJSON export, clear |
| `lifecycle.go` | `agent11 hook` client and Claude Code mapping, hook socket server, provider and model extraction |
| `lifecycle_query.go` | Lifecycle fold (time in state, blocked, turns, waits, errors, stalls), launch stats, resource usage |
| `adapters.go` | Declarative hook-adapter engine: add a new agent via `<name>.json` in the adapters dir (`~/.config/agent11/adapters/`, see `docs/adapters/example.json`) |
| `guard.go` | Clipboard guard: trigger rules, notice text, clipboard writers, AI-context checks |
| `intake.go` | Optional `/scan` and `/healthz` HTTP endpoint with bearer-token auth |
| `rotate.go` | `rotatingFile`, a size and line-count rotating `io.Writer` |
| `policy.go` | Load and validate the JSON policy; `Verdict`; class definitions; destination matrix; path globs |
| `decide.go` | The decision pipeline (`decider.decide`); returns a `Decision`; classifier features |
| `classify.go` | `Classifier` interface, `noopClassifier`, the Jev implementation |
| `proxy.go` | LLM reverse proxy; calls `decide`; blocks or forwards; block response shape |
| `events.go` | `Sink` interface and the logfmt file sink |
| `translate.go` | `Translator` interface stub for surrogate values (DPTP) |
| `eval.go` | The `-eval` mode that scores the pipeline against a labeled corpus |
| `policy.example.json` | Example policy; the real classes are an owner decision |
| `testdata/corpus/` | Synthetic labeled samples, `<class>.positive.txt` / `<class>.negative.txt`, `---` between samples |
| `docs/ARCHITECTURE.md` | Architecture and design decisions: components, endpoints, storage, access, failure behavior |
| `docs/CAPABILITIES.md` | Plain-language capabilities overview for product and sales use |
| `docs/ROADMAP.md` | Phased plan: OS-level (`lsof`/`/proc`), network, browser, and enforcement |

Planned: an HTTP sink for SwarmSentinel in `events.go` (phase 2).

## Platform behavior

Clipboard reads shell out to `pbpaste` (macOS), PowerShell `Get-Clipboard` (Windows), or `wl-paste`, `xclip`, `xsel` (Linux, first one found). Process listing uses `ps` on Unix and `tasklist` on Windows, where only image names are available, so command-line patterns never match there. Every external command runs under `readTimeout` (3s) so a hung helper cannot stall the loop.

## Invariants to preserve

These are deliberate privacy and safety choices. Do not weaken them without being asked.

Existing:

- DLP `scan` returns rule names and counts only, never the matched text. Log `dlp=` summaries, not values.
- With `-log-content=false`, raw clipboard and intake text must never reach the log.
- The intake endpoint refuses non-loopback addresses (`isLoopback`), compares tokens with `subtle.ConstantTimeCompare`, caps bodies at `maxIntakeBytes`, and prints a generated token to stderr only, never to the log.
- Browser watching logs the host only, never the URL path or query.
- Process command lines go through `sanitizeCmd` (redacts key/token/secret args, truncates to 300 chars) before logging.
- Log files are created with mode `0600`.
- Repeated errors are logged once per distinct message (`lastErr` pattern), not on every tick.
- The metrics store is body-free: rows hold kinds, labels, counts, timings, and token-usage integers, never clipboard text, request content, prompts, responses, or command lines. Intake source and site labels are capped at 64 bytes. The database is created 0600 in a 0700 directory; symlinks are refused.
- `agent11 hook [--agent <kind>]` maps each agent's own hook payload to a lifecycle event and keeps only the event name, opaque IDs (c11's rule: printable ASCII, no spaces or slashes, at most 128 bytes) and a model name. Claude Code is the default; `--agent antigravity` reads Antigravity's `conversationId`/`toolCall`/`modelName` payload. It never forwards prompts, tool input or output, transcript or workspace paths, or notification text. It never forwards prompts, tool input or output, or notification text, prints nothing to stdout, and always exits 0. The hook socket is 0600 in a 0700 directory, and the server re-validates every field.
- `Record` never blocks a caller: a full buffer drops the event and counts it in `meta.dropped_events`.
- The clipboard guard is off by default. Its notice names rules and counts only, and guarded text is never logged, whatever `-log-content` says.

New, for the enforcement work:

- A `Decision` carries class IDs, rule names, confidence, verdict, mode, agent ID, and destination host. It never carries request content, matched text, or prompts. The same holds for every event sent to a sink.
- The proxy binds to loopback only, reusing `isLoopback`. It does no TLS interception. Agents reach it through a base-URL override (for example `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` pointing at `http://127.0.0.1:<port>`).
- Request bodies are capped. Streaming responses pass through as they arrive; the proxy scans them in flight only to read the `usage` token counts, keeping the integers and never buffering or storing the body. The proxy never stores a request or response body, in memory beyond the request or on disk.
- API keys and authorization headers pass through to the upstream and are never logged.
- A hosted classifier never receives raw request content by default. It receives features (path labels, document markers, length, rule counts) or text that has already been through the `Translator`. A class may opt in to raw content only with `"classifier_raw": true` in the policy, and that choice must be visible in the startup log.
- Hard rules are deterministic. Source labels, fingerprints, patterns, and path denies never wait on a classifier and never depend on a probability.
- Default mode is report-only. Enforcement is switched on per class in the policy file, never globally by default.
- Agent identity from a header or environment variable is a hint, not proof. Label it `agent_id_source=declared` in events until a trusted launcher exists.

## Decision pipeline

Evaluate signals in this order and stop at the first definite hit:

1. **Source labels.** Data read from a labeled source (repo, directory, share, database) carries that label forward. Labels come from the policy file and from `X-Agent11-Labels` request headers set by trusted launchers.
2. **Fingerprints.** Exact hashes of known documents, customer ID lists, project codenames.
3. **Patterns and keywords.** The rules in `dlp.go` plus per-class rules from the policy.
4. **Classifier.** Only for text that steps 1 to 3 left ambiguous, and only if the class enables it.

As built: steps 1 to 3 are cheap, so they run for every class (path globs count with source labels). Stopping early would let one class's hit hide a stricter class. The classifier then runs only for enabled classes with no deterministic hit whose action at this destination is stricter than the verdict so far. A deterministic `block` skips it entirely.

Verdicts: `allow`, `translate`, `hold`, `block`. In phase 1, `hold` behaves like `block` with a message that tells the user how to request an exception. `translate` is treated as `block` until a real `Translator` exists.

Mode applies after the verdict. In report mode the proxy forwards the request and logs `enforced=false` with the verdict that would have applied. In enforce mode it applies the verdict.

Failure behavior:

- Classifier timeout or error: fall back to steps 1 to 3. If the source is labeled sensitive, block. Otherwise allow and log `classifier=unavailable`.
- Policy file invalid at startup: refuse to start. Policy file invalid on reload: keep the last good policy and log once.
- Policy file missing the destination in a request: treat it as the strictest destination category.

## Policy file

JSON, because the standard library has no YAML parser. Classes are data. Adding a class must not require a code change.

```json
{
  "version": 1,
  "mode": "report",
  "destinations": {
    "approved-tenant": ["api.company-llm.example"],
    "consumer-chat": ["chatgpt.com", "claude.ai", "gemini.google.com"],
    "public-api": ["api.openai.com", "api.anthropic.com", "openrouter.ai"]
  },
  "classes": [
    {
      "id": "source-code",
      "description": "Proprietary application source code",
      "owner": "engineering",
      "detectors": {
        "source_labels": ["repo:core-platform"],
        "path_globs": ["**/core-platform/**"],
        "keywords": ["ProjectX"],
        "rules": []
      },
      "classifier": {
        "enabled": true,
        "block_at": 0.90,
        "hold_at": 0.50,
        "classifier_raw": false,
        "examples_positive": [],
        "examples_negative": []
      },
      "actions": {
        "approved-tenant": "allow",
        "consumer-chat": "block",
        "public-api": "block"
      },
      "mode": "report"
    }
  ]
}
```

Rules for the schema:

- Every class needs `id`, `description`, `owner`, and an `actions` entry for every destination category.
- `detectors.rules` entries are a built-in rule name from `dlp.go` (`"aws-access-key"`) or a regular expression prefixed with `re:`.
- `detectors.fingerprints` (optional) holds lowercase hex SHA-256 hashes. A request matches when the hash of its whole text, or of any trimmed line of 20 or more bytes, is listed.
- `classifier.hold_at` of 0 means no hold band.
- Unknown fields are rejected, so a typo cannot silently disable a detector.
- Per-class `mode` overrides the global mode.
- Keep examples short. A class definition sent to a classifier should stay near 200 tokens.
- Validate at load time and report the first error with the class ID and field name.
- Never put real secrets or real customer data in a policy file or its examples.

## Classifier

`Classifier` is an interface in `classify.go`. The pipeline depends on the interface, not on a vendor.

Jev is the first implementation:

- Jev is TypeSafe's System One model. It takes state plus typed questions and returns a typed decision with probabilities, not text. It is hosted, reached through OpenRouter, and billed per input token.
- Pin the model version (`typesafe/jev-1.13`), never the `latest` alias, while calibrating. Make the model ID a flag or policy field.
- Context is 32K tokens. Chunk long input and take the highest class probability across chunks.
- Send one typed question per call, built from the enabled class definitions. Class definitions come from the policy file at call time.
- Set a short timeout and one retry at most. Never let a slow classifier stall the request path beyond the timeout.
- Treat output as advisory evidence. A wrong label from manipulated text is possible, so hard rules stay outside the classifier.
- Check the current API, model ID, and pricing in the OpenRouter and TypeSafe docs before writing the client. Do not rely on this file for request or response shapes.

A second implementation that runs locally (a downloadable System One model) is a likely follow-up. Do not hard-code Jev assumptions outside `classify.go`.

## SwarmSentinel integration

SwarmSentinel is a separate project (the Agent Security Policy engine with a gateway, tripwires, and a flight recorder). agent11 produces decisions and events. SwarmSentinel consumes them.

Rules:

- **Read the SwarmSentinel repo before writing the adapter.** Find its event model and ASP policy schema there. Do not guess field names. If the schema lacks a field you need, write down the gap in `docs/swarmsentinel-gaps.md` and propose the change instead of inventing a field.
- **Keep it behind `Sink`.** The default sink writes logfmt to the rotating log. The HTTP sink posts to a SwarmSentinel endpoint. Selecting a sink is a flag. agent11 must run with no SwarmSentinel present.
- **No vendored code.** Do not copy SwarmSentinel code into this repo. Talk to it over HTTP. The two projects have different licenses, and separate processes keep them separate.
- **Auth.** The hosted SwarmSentinel routes expect a verified session. For local use, use a shared secret over loopback or a Unix socket. Never write the secret to the log.
- **Confidentiality is a new dimension.** SwarmSentinel's existing content trust tracks integrity (untrusted data coming in). Data leakage is confidentiality (sensitive data going out). Send class IDs as labels and let SwarmSentinel propagate them across agents. Do not reuse its integrity fields for this.
- **Events.** Emit one event per decision with the `Decision` fields, `agent_id_source`, and a timestamp. Include enough for the recorder to rebuild an incident timeline without content.

## Agent coverage

agent11 must work for any agent, so each integration path has a defined role and known limits.

| Path | How it connects | Can block | Limits |
| --- | --- | --- | --- |
| CLI and SDK agents (Claude Code, scripts, others) | Base-URL override to the proxy | Yes | Only tools that honor a base-URL setting |
| Claude Code hooks | `UserPromptSubmit` and `PreToolUse` hooks call `/scan` | Yes | Claude Code only; hooks must also cover file reads |
| Clipboard | Polling watcher; `-clipboard-guard` overwrites the clipboard on a match (`ai`: while an AI site in Chrome or a desktop AI app is open) | Partly | Race between polls; typed text not covered; AI context only from Chrome on macOS and the process list |
| Browser chats | Extension posts to `/scan` and blocks submit | Yes, with extension | Needs a managed extension; not built yet |
| Desktop AI apps | Process watching for inventory | No | Needs network egress rules to block |
| Other machines and employees | Out of scope for the local binary | No | Needs endpoint rollout and an egress gateway |

A local tool stops accidents, not deliberate exfiltration through another device. Say so in any user-facing docs.

## Phases

**Phase 1 (target: 2 to 3 weeks).** Policy file, `decide`, proxy, `Classifier` with Jev behind it, file sink, `-eval`. Report mode by default.

Exit criteria. These are proposals, so confirm them with the owner before treating them as final:
- Miss rate under 5% per class on at least 200 labeled samples.
- Under 2% false positives on normal traffic.
- Added proxy latency under 100 ms at p95.
- Two weeks of report-only data reviewed.

**Phase 2.** HTTP sink to SwarmSentinel, recorder and dashboard, confidentiality labels in the ASP schema, taint across agents, a local approval flow for `hold`, a `Translator` implementation.

**Phase 3.** c11 integration: trusted agent identity at panel spawn, labels from launchers, sidebar status, panel suspend on repeated violations. Only start if developer workstations running agent swarms are a confirmed target.

## Testing

- Every new rule, policy validation, and decision path gets a table-driven test beside the code.
- `testdata/corpus/` holds labeled samples as one file per class and label. Use synthetic data only. Never commit real secrets, real customer data, or real company documents.
- Rules match structure, not real values. Build test strings from patterns.
- `-eval` prints per-class miss rate, false-positive rate, and latency percentiles. Do not switch a class from report to enforce in the policy example without eval numbers in the commit message.
- The proxy needs tests for: block response shape, streaming passthrough, body cap, loopback-only binding, no content in logs, and classifier timeout fallback.

## Extending

- New AI desktop or CLI app: add an `app(...)` entry to `aiApps` in `procwatch.go` using `macApp`, `exeName`, or `contains`. Order matters: the first match wins, so put specific bundle matches before broad executable names.
- New AI website: add the host suffix to `aiSites` in `browserwatch.go`.
- New DLP rule: add to `builtinRules` in `dlp.go`. Match on structure, not real values, and add a `validate` func when the pattern alone is noisy (see `luhnValid`).
- New company class: add an entry to the policy file. No code change.
- New LLM API provider for the proxy: add its host to the destination lists and check how it carries the model and body, so size caps and streaming still work.
- New flag: define it in `main()` alongside the others and include it in the `agent11 started` log line if it affects behavior.

## Conventions

- Comments explain why, at the density already in the files. Match it.
- Wrap errors with `fmt.Errorf("context: %w", err)`; join multiple with `errors.Join`.
- Log with `slog` key/value pairs, short lowercase messages (`"ai app started"`, `"clipboard read failed"`, `"request blocked"`).
- Never commit `agent11` (the binary) or `*.log` files; logs can contain captured clipboard data.
- Keep commits small and tied to one component. Update the Status and Layout tables in the same commit that changes them.
- Ask before adding a dependency, changing an invariant, or changing the policy schema version.

## Non-goals

- Reading or storing prompts, response content, or documents. (Token-usage counts read from a response are integers, not content.)
- TLS interception or system-wide traffic capture.
- Replacing a network egress gateway or an MDM-managed endpoint agent.
- Judging whether data is legally privileged. Companies define classes. Counsel defines what they mean.

## Open decisions for the owner

Ask the owner before building on any of these:

- Phase 1 exit thresholds and the first 3 to 5 company classes.
- Hosted classifier on features only, on surrogate text, or a self-hosted model.
- The SwarmSentinel event and policy fields once the repo review is done.
- Whether employee monitoring needs HR and counsel review before rollout. In California, employee data falls under the CCPA.
