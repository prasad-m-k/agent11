# agent11 Roadmap

Where agent11 is and what comes next. Each phase is a working product, and the order is deliberate: see everything first, then control it, then make it hard to bypass. Deployment-time concerns (consent notices, data-retention policy, legal review) are wired in at the phase a feature ships to real machines, not before; this is a prototype.

Dates are not fixed. "Done" means built and tested in this repo, not released.

## Done

| Phase | What shipped |
| --- | --- |
| 1: See | Clipboard, process, and Chrome-tab watching; DLP scan for secrets, PII, and company keywords; rotating log |
| 1: Decide | JSON policy of data classes and destinations; the decision pipeline (labels, fingerprints, patterns, classifier); loopback LLM reverse proxy in report or enforce mode; Jev classifier behind a vendor-neutral interface; `-eval` against a labeled corpus |
| 1.1: Measure | Body-free metrics in local SQLite; agent lifecycle metrics from Claude Code and Antigravity hooks (time in state, blocked time, turns, operator waits, errors, stalls); launch stats; CPU and memory per AI app; `agent11 metrics query/export/clear` |
| 1.1: Extend | Declarative hook adapters: add a new agent by dropping a JSON file in the adapters directory, no recompile (`agent11 hook --list-agents`, `--print-config <agent>`) |
| 2: Show | Local web dashboard (`agent11 dashboard`, default `127.0.0.1:9090`) over the metrics database: agent inventory with running-now status, activity timeline, data-protection decisions, resource use |

## Next: deeper capture at the OS level

These widen what agent11 can see. They were deferred because capturing process, file, and network data across the machine is sensitive, and the harness gates it behind explicit authorization. Each needs a data-handling decision before it is built.

### 1.2: Process and file inspection (`lsof` / `/proc`)

- **Process tree and detail** for every detected agent: parent and child processes, working directory, run duration, owning user. Turns the flat inventory into the real agent tree.
- **Open files per AI process** (via `lsof` on macOS, `/proc/<pid>` on Linux, handle enumeration on Windows): which repositories, config files, and credential files an agent has open. This is the clearest signal of what data an agent is actually working with.
- **Why gated:** reading other users' processes needs root, and file paths and process arguments can themselves be sensitive. Store paths as coarse labels or hashes by default, raw only under an access-controlled policy.
- **Dependencies:** none beyond elevated privileges when inspecting other users.

### 1.3: Network-level visibility

- **Connection sampling:** poll connections (`lsof -i`, `netstat`, or an eBPF/pktap source) and record which process is talking to which remote host and port.
- **LLM traffic detection without the proxy:** match remote endpoints against resolved LLM API hosts, so agent11 sees an agent reaching a model even when it was never pointed at the proxy. This is the single biggest closer of the "an agent we have no signature for" gap in the inventory.
- **Why gated:** capturing the network activity of all processes is monitoring that handles sensitive metadata; it must be an explicit, authorized capability.
- **Dependencies:** on macOS, elevated privileges for system-wide connection views.

### 1.4: Richer reporting

- Fold process, file, and network signals into the dashboard: an activity timeline per agent, the hosts each agent reached, and the files each touched. Depends on 1.2 and 1.3.

### 1.5: IDE plugins for built-in IDE AI

- A managed JetBrains plugin and VS Code extension that observe the IDE's built-in AI (JetBrains AI Assistant and Junie, VS Code Copilot Chat) and post lifecycle and token-usage events to agent11's hook socket. This is the IDE counterpart of the browser extension in 3.3.
- Why needed: built-in IDE AI runs inside the IDE process (no distinct process to detect) and sends TLS straight to its own backend, so neither the process watcher nor the proxy sees it. Copilot's language server is detected as present today, but with no turns or tokens.
- The ingestion side already exists: the hook socket and the declarative adapter engine accept any agent, so each IDE needs only a `<name>.json` adapter plus the plugin that emits the events. A `jetbrains-ai` adapter template is the first small step.
- Limits: completeness depends on what each IDE's plugin API exposes about its AI activity; JetBrains AI Assistant offers limited public hooks for its own requests. Where a plugin cannot see enough, network capture (1.3) gives presence and the backend provider, and TLS inspection (3.4) gives full content and tokens.
- Force-installing the plugin so a user cannot remove it is a managed-deployment (MDM) step, like the browser extension in 3.3; an observe-only install needs no MDM.

## Then: enforcement

agent11 can observe and, through the proxy, block. These make blocking real across every channel.

### 2.1: Enforce in the agent hooks

- The hook integration already receives each tool call before it runs. Return a deny decision when a prompt or tool input matches a blocking class. Antigravity's `PreToolUse` and Claude Code's `PreToolUse` / `UserPromptSubmit` both support this.
- Deploy through each tool's managed settings so a user cannot remove the hook.

### 2.2: Unapproved-app control

- An app allowlist in the policy. Unapproved desktop AI apps are reported, then (on enforce) closed on sight.

### 2.3: Clipboard guard on by default

- Turn the existing clipboard guard on through policy, poll faster, and keep blocked content as access-controlled evidence rather than discarding it.

### 2.4: Central feed

- The SwarmSentinel / SIEM sink: decision events, and content evidence for blocked events, sent to a central policy engine and recorder. Already stubbed behind the `Sink` interface.

## Later: hard to bypass

These require device-management (MDM) deployment, not just the local binary.

### 3.1: Forced egress

- Firewall rules (macOS `pf`, Windows Filtering Platform) installed by MDM that refuse direct connections to known LLM hosts, so all LLM traffic must pass through agent11's proxy.

### 3.2: Run as a protected service

- A system service (root daemon on macOS, Windows service) users cannot stop, with heartbeats to a central server and alerts on gaps.

### 3.3: Browser coverage

- A managed browser extension (Chrome, Edge) force-installed by MDM that checks paste, typed prompts, and file uploads on AI sites with agent11 and blocks the submit. Closes the one channel a process-level tool cannot reach. The IDE-plugin counterpart is 1.5.
- MDM can also block unapproved AI sites outright.

### 3.4: Desktop app traffic inspection

- Decrypt and inspect desktop AI apps' traffic with a company certificate installed by MDM. This reverses the current "no TLS interception" non-goal and is an explicit deployment choice, not a default.

## Cross-cutting, added as features reach real machines

- **Transparency:** a known, non-hidden service with a notice to users. Covert monitoring is out of scope.
- **Data handling:** capture broadly, store narrowly. IDs and metadata by default; full content only as access-controlled evidence for blocked events.
- **Consent and legal:** employee-monitoring review with HR and counsel before fleet rollout. Employee data falls under the CCPA in California and the GDPR in the EU.
- **True all-time counters:** an un-pruned aggregate (launches by model and provider) that survives the retention window, matching c11's launch-stats aggregate.
