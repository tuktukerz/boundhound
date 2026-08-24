# Boundhound

**A pentest agent for Claude Code with enforced, deny-by-default scope safety.**

---

## 🚧 Status: Phase 1 — Recon

```
[0] Foundation & Safety   ██████████ done
[0.5] Plugin packaging    ██████████ done
[1] Recon                 ██████████ done   <- you are here
[2] Enumeration           ░░░░░░░░░░ not started
[3] Exploitation          ░░░░░░░░░░ not started
[4] Verification          ░░░░░░░░░░ not started
[5] Reporting             ░░░░░░░░░░ not started
[6] Orchestrator          ░░░░░░░░░░ not started
[7] Expansion             ░░░░░░░░░░ not started
```

**Phase 0 was deliberately zero-attack-capability.** No nmap, nuclei, or sqlmap — just `curl` as a bridge tool for testing. The principle: **fences first, weapons later.** No offensive tool gets installed before the safety layer bounding it is proven by automated tests.

**Phase 0.5 made that same safety layer installable as a plugin**, so it runs from any project directory instead of only from inside this repo checkout. It changed nothing about the enforcement logic — only *where* it reads code from and writes state to.

**Phase 1 adds the first real attack-surface-mapping capability: recon** — subfinder, httpx, and nmap, all still running through the same `bh-exec` choke point proven in Phase 0. See **Recon** below.

## Why this exists

An autonomous pentest agent is dangerous without hard limits. Most "AI pentest" tools rely on the agent *choosing* to respect scope — that's a request, not enforcement. Boundhound inverts that: **the agent is technically unable** to touch out-of-scope targets, because enforcement lives in a layer the agent doesn't control (a git-tracked hook + a CLI choke point), not in a prompt.

## How the safety works

```
User / Agent
    │
    ▼
┌─────────────────────────┐   direct command to curl/nmap/etc?
│  PreToolUse hook         │──────────────► DENY (bypass blocked)
│  (scope-guard.mjs)       │
└─────────────────────────┘
    │ passes through bh-exec
    ▼
┌─────────────────────────┐   target outside scope.yaml?
│  bh-exec                │──────────────► DENY + audit log
│  (choke point)           │
│  scope → safety → audit  │
└─────────────────────────┘
    │ ALLOW
    ▼
┌─────────────────────────┐
│  docker exec             │  tool runs in an isolated container
│  (bh-<engagement>)      │
└─────────────────────────┘
```

- **Deny-by-default** — a target not explicitly listed in `in_scope` is rejected. When in doubt, rejected.
- **Fail-closed** — a broken `scope.yaml` or no active engagement means everything is rejected.
- **`out_of_scope` wins** over `in_scope` — explicit exclusions always take priority.
- **Two independent layers** — the hook stops the agent from *avoiding* `bh-exec`; `bh-exec` itself does the real check.
- **Full audit trail** — every decision (ALLOW/DENY) is logged: timestamp, target, tool, reason, authorization.

All of this is verified by [`test/acceptance.test.mjs`](test/acceptance.test.mjs) and [`test/plugin-e2e.test.mjs`](test/plugin-e2e.test.mjs) — not a claim, there's proof:

```bash
bun test   # 181 pass · 1 skip (Docker smoke, needs a live container) · 0 fail
```

## Recon

Phase 1 chains three tools against the active engagement's in-scope
targets, orchestrated by the self-authored `pentest-recon` skill (run via
`/recon`):

1. **`subfinder`** — passive subdomain discovery against the in-scope root domain.
2. **`httpx`** — HTTP probing (status code, title, tech detection) of the root domain and any discovered subdomain that clears scope.
3. **`nmap`** — port and service/version scanning of every live host `httpx` found.

Every one of those three invocations goes through `bh-exec` exactly like
any other tool — scope-checked, safety-capped, audited, and run inside the
engagement's container. Nothing in recon gets a shortcut around the choke
point proven in Phase 0.

A final step, `bh-recon-map` (`bin/bh-recon-map.mjs`), reads the raw
`subfinder`/`httpx`/`nmap` output already on disk and normalizes it into
one `recon-map.json`, written to
`engagements/<name>/output/recon/recon-map.json`.

**Probing a discovered subdomain requires opting in to it in scope.**
`subfinder` will often discover subdomains that were never typed into
`scope.yaml` directly. A literal entry like `acme.io` matches only that
exact host — it does not cover `api.acme.io`. To let `httpx`/`nmap` touch
subdomains `subfinder` discovers under `acme.io`, `in_scope.domains` must
explicitly include a wildcard entry, e.g. `"*.acme.io"`. Without it, recon
still records every discovered subdomain in `subfinder.jsonl`, but does not
probe or scan any of them.

This is proven by a real, non-mocked end-to-end test —
[`test/recon-e2e.test.mjs`](test/recon-e2e.test.mjs) — which spins up an
actual local target container and runs the real `nmap`/`httpx` binaries
against it through `bh-exec`, driving the actual CLIs exactly as an
operator would.

## Install as a Claude Code plugin

```
/plugin marketplace add tuktukerz/boundhound
/plugin install boundhound@tuktukerz-marketplace
```

Once installed, the **scope-guard hook enforces from any project directory** — you no longer need to be inside this repo checkout for the safety layer to be active. This is a hard guarantee: Claude Code exports `${CLAUDE_PLUGIN_ROOT}` directly to the hook's subprocess environment, and it's proven by `test/plugin-e2e.test.mjs`, which runs the hook from a foreign cwd with nothing pointing at this repo and confirms the DENY + audit trail still land correctly.

`/engagement` and `/mode` are wired the same way — their instructions invoke `node "${CLAUDE_PLUGIN_ROOT}/bin/bh-engagement.mjs" ... --data-dir "${CLAUDE_PLUGIN_DATA}"` rather than a bare relative path — but that convenience path depends on Claude Code resolving both placeholders inline in skill/command content and the agent following the written instruction, which is a documented mechanism but not the same kind of hard runtime guarantee the hook has. See **Known limitations** below.

Engagement state (scope files, `.active`, audit logs) lives under the plugin's own data directory (`${CLAUDE_PLUGIN_DATA}`), so it persists across plugin updates instead of being wiped when the plugin's code is refreshed. The CLI (`bh-exec.mjs` / `bh-engagement.mjs`) receives that path via an explicit `--data-dir "${CLAUDE_PLUGIN_DATA}"` argument, content-substituted the same way `${CLAUDE_PLUGIN_ROOT}` already is in the script path — **not** by reading `CLAUDE_PLUGIN_DATA` as an environment variable at runtime. That distinction matters: Claude Code exports `CLAUDE_PLUGIN_DATA` as a real env var only to hook/MCP/LSP subprocesses, not to the agent's Bash tool session, so a CLI process spawned via Bash never sees it in its own `process.env` — without `--data-dir`, `dataRoot()` would silently fall back to the current working directory instead. Passing it explicitly as a CLI argument is what makes the CLI's state and audit log land in the same directory the hook (which does get the env var) already uses — see `test/plugin-cli-data-dir.test.mjs`.

## Known limitations

- **One active engagement per installation.** Engagement state — including the single `.active` pointer file — lives under one shared `${CLAUDE_PLUGIN_DATA}` directory for the whole plugin installation, not per-project. Treat only one engagement as active at a time. Running different engagements concurrently from different project directories against the same installed plugin is **not yet supported**: they would share `.active` and could misattribute the audit trail (e.g. a tool run kicked off from project B could get logged against project A's engagement). This is a known gap for future work, not a safety bug — the deny-by-default/fail-closed guarantees still hold for whichever engagement is actually active.
- **`/engagement` and `/mode` are agent-instruction-dependent, not hook-enforced.** They rely on the agent following the `${CLAUDE_PLUGIN_ROOT}`/`${CLAUDE_PLUGIN_DATA}`-qualified invocation written into the `pentest-mode` skill and command files (see that skill's "Invoking the scripts" section). The scope-guard hook has no such dependency — it is registered directly with Claude Code and fires unconditionally.

## Run from a clone (dev mode)

The alternative to installing as a plugin: clone the repo and run everything locally, with state kept inside the checkout (`$CLAUDE_PROJECT_DIR`) instead of `${CLAUDE_PLUGIN_DATA}`. Useful for developing Boundhound itself.

```bash
bun install
bun test                        # 181 pass / 1 skip

bin/bh-container up smoke     # start the tool container
node bin/bh-engagement.mjs acme   # scaffold a new engagement -> fill in scope.yaml
node bin/bh-exec.mjs curl --target api.acme.io -- -I   # run a tool through the choke point
```

In dev mode, omit `--data-dir` entirely — both scripts fall back to `$CLAUDE_PROJECT_DIR`/cwd (see `dataRoot()` in `src/paths.mjs`). `--data-dir <path>` is accepted by both scripts in any mode and, when passed, always wins over the env-var fallback.

## Structure

```
.claude-plugin/
  plugin.json              plugin manifest (skills/commands/hooks entry points)
  marketplace.json         self-hosted marketplace so the repo is /plugin-installable
.claude/
  skills/pentest-mode/     active skill (engagement mode + scope selector)
  skills/pentest-recon/    active skill (Phase 1 recon orchestrator: subfinder -> httpx -> nmap -> bh-recon-map)
  commands/                /engagement, /mode, /recon
  settings.json            PreToolUse hook registration (dev/project mode)
bin/
  bh-exec.mjs            choke point: scope + safety + audit -> docker exec
  bh-engagement.mjs      scaffold a new engagement
  bh-recon-map.mjs       merges subfinder/httpx/nmap output into recon-map.json
  bh-container           Docker container lifecycle
hooks/
  scope-guard.mjs          blocks bh-exec bypass attempts
  hooks.json               PreToolUse hook registration (plugin mode, ${CLAUDE_PLUGIN_ROOT})
src/
  paths.mjs                code root vs data root resolution (plugin vs local-project)
  scope/                   parser + matcher (deny-by-default) + fail-closed resolver
  safety/                  blocks destructive/DoS actions
  catalog/                 tools-catalog.json loader (ToolEntry schema)
  guard/                   command classification, anti-bypass
  audit/                   JSONL audit log
  recon/                   recon-map.mjs: normalizes subfinder/httpx/nmap output into recon-map.json
docker/Dockerfile          multi-stage image — nmap + subfinder + httpx (Phase 1 recon tools)
skills-library/            authored skill library (promoted to active per phase)
docs/
  ARCHITECTURE.md          big-picture map & 8 phases
  specs/, plans/           spec & implementation plan per phase
```

## Design principles

1. **Safety before capability.** Every new capability phase (recon, exploit, etc.) is built on a foundation that has already passed its tests — not the other way around.
2. **Skills are authored, not imported.** Each active skill is written for Boundhound's own config and enforcement model, and promoted one phase at a time alongside the tools it orchestrates — never shipped ahead of the safety layer that bounds it.
3. **Enforcement, not instruction.** When something must hold true, it's enforced by code/hooks — not just written into agent instructions.
4. **Every task = TDD + adversarial review.** Built via subagent-driven development: each module is written test-first, reviewed by an independent subagent, and every finding (including real bugs — a guard bypass, a fail-open hook, a dead `import.meta.main` check on Node) is closed with a regression test before moving on.

## Roadmap

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full map of all 8 phases, design decisions, and the reasoning behind each architectural choice.

---

*Built iteratively: brainstorming → grilling → spec → plan → subagent-driven implementation, each step reviewed before moving on.*
