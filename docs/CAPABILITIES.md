# agent11 Capabilities

A plain-language description of what agent11 does today, written so it can be reused in product and sales conversations. It is honest about what is built versus planned, because a security tool that overstates itself loses trust on the first demo. Current as of the phase 2 dashboard.

## The one-line version

agent11 is a single program that runs on a workstation and gives a company visibility into how AI tools and coding agents are being used on that machine, and what company data is at risk of reaching them. It watches, measures, and reports today. It is built to enforce later.

## The problem it addresses

Employees now use AI coding agents (Claude Code, Antigravity, Cursor, Codex and others), desktop AI apps, and browser chatbots throughout the workday. Each of these can send source code, customer data, credentials, or internal plans to an outside model. Most companies have no idea which AI tools are running on their machines, how heavily they are used, or what data is flowing to them. agent11 answers those questions first, so a company can see the picture before deciding what to control.

## What agent11 sees today

- **AI tools and agents in use.** agent11 scans the process list against a catalog of known AI desktop apps and coding agents (Claude Code, Antigravity, Codex, Gemini CLI, Aider, opencode, Goose, Amp, Crush, Cline, Roo Code, Cursor, Windsurf, local model runners, and more), and reports which are running now, when they started and stopped, how long they ran, and their CPU and memory. The dashboard shows this as a live inventory of agents on the machine. Which AI websites are open in the browser is tracked too.
- **Agent activity, in depth.** For agents that support it (Claude Code and Antigravity today, via their own hook systems), agent11 measures how long each agent spends working, blocked waiting on a human, idle, or in error; how many turns it runs; how long people take to respond to it; and where it stalls. This is the same class of operational metric a mature agent platform tracks about itself.
- **LLM requests and token usage.** When agents are pointed through agent11, it sees every request to an LLM API: which model, which provider, which agent, and whether the content matches a company data class. It records the decision, how long the decision took, and the token usage (input and output) read from the response. Token data covers proxied requests only.
- **Sensitive data on the move.** It scans the clipboard and submitted text for secrets (API keys, private keys, tokens), personal data (card numbers, national IDs, emails), and company-defined markers such as project codenames or confidentiality labels.
- **Resource cost.** CPU and memory used by each AI tool, and by agent11 itself, so the overhead of both is visible.

## What it does with that

- **A local metrics database.** Everything is recorded in a SQLite database on the machine, retained for a configurable window (30 days by default) and hard-capped in size. It can be queried from the command line or exported.
- **A dashboard.** `agent11 dashboard` serves a web page, on the local machine only, showing AI tool usage, agent activity, data-protection decisions, destinations and models, and agent11's own overhead, with an activity-over-time chart and adjustable time range.
- **Data-loss decisions.** A company policy file defines data classes (source code, customer data, credentials, and so on) and where each may or may not go. agent11 classifies each LLM request against that policy and records a verdict: allow, flag, or block.

## How it classifies data

Classification is layered, and the cheap and certain checks come first:

1. **Source labels** a trusted launcher attaches to a request.
2. **Fingerprints** of known documents or data.
3. **Patterns and keywords**: the built-in secret and personal-data detectors, plus the company's own class rules.
4. **A classifier** for the text those steps leave ambiguous, and only then.

The deterministic steps cannot be talked out of a verdict by cleverly worded text, and they cost nothing. The classifier is advisory and, by default, sees only a description of a request (labels, folder names, document markers, size, rule counts), never the content itself, unless a class explicitly opts in.

## Privacy and data handling by design

This matters for both trust and compliance, and it is a design choice, not an afterthought:

- The metrics database and the dashboard hold counts, labels, and timings only. They never store prompts, responses, request bodies, command lines, or file contents.
- The agent hook integration forwards only event names and opaque IDs. It never forwards prompt text, tool input or output, or file paths.
- Everything is local. The two network listeners (the LLM proxy and the scan endpoint) bind to the loopback interface only and refuse any other address. The dashboard is loopback only.
- Files are created readable by the owner only.

These rules keep agent11 from becoming the very data store it is meant to protect, and they are what separate legitimate enterprise monitoring from surveillance.

## Agent and channel coverage

| Channel | What agent11 does today |
| --- | --- |
| Claude Code, Antigravity | Full lifecycle metrics through each tool's native hooks |
| CLI and SDK agents pointed at the proxy | Per-request classification and decision |
| Desktop AI apps and CLI agents (ChatGPT, Cursor, Codex, opencode, local models, and more) | Detected from the process list and measured: presence, run time, CPU, memory, process count |
| Clipboard | Scanned on every copy; can optionally replace a sensitive copy with a notice |
| Browser AI sites | The open site is detected; content in the page is not yet inspected |

Detection is process-level. An agent that runs only as an editor extension with no distinct process of its own, or one agent11 has no signature for, will not appear in the inventory until network-level and session-log signals are added in a later phase. Deep per-agent metrics (turns, blocked time, operator waits) need that agent's hooks or session logs; today that is Claude Code and Antigravity.

## Deployment shape

agent11 is a single binary with one dependency (a pure-Go SQLite engine), so it cross-compiles for macOS, Windows, and Linux and deploys as one file. It runs as the user today. Running it as a managed system service, forcing agent traffic through it, and a force-installed browser extension are deployment steps that come with the enforcement phase.

## Where it is going

agent11 is built in phases, each one a working product:

1. **See** (done): detect AI use, classify requests, measure agent activity, store and report it.
2. **Decide and show** (done): the policy, the decision pipeline, the metrics store, and the dashboard.
3. **Enforce** (next): block in the agent hooks, close unapproved apps, a guarded clipboard on by default, and a central reporting feed.
4. **Hard to bypass** (later): a managed system service, forced egress through agent11, and browser coverage through a managed extension.

The sequence is deliberate. A company gets the full picture of AI use and data exposure first, in report mode, and turns on enforcement class by class once the picture is understood and the false-positive rate is known.
