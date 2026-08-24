# Boundhound

**Autonomous pentest agent, built natively on Claude Code.**

> Not a fork. OmOP ([`zakirkun/oh-my-open-pentest`](https://github.com/zakirkun/oh-my-open-pentest)) is used as a skill mine and pattern reference — the orchestrator, safety layer, and integration are built from scratch on top of Claude Code primitives (skills, subagents, hooks).

---

## 🚧 Status: Phase 0.5 — installable as a Claude Code plugin

```
[0] Foundation & Safety   ██████████ done   <- you are here
[0.5] Plugin packaging    ██████████ done
[1] Recon                 ░░░░░░░░░░ not started
[2] Enumeration           ░░░░░░░░░░ not started
[3] Exploitation          ░░░░░░░░░░ not started
[4] Verification          ░░░░░░░░░░ not started
[5] Reporting             ░░░░░░░░░░ not started
[6] Orchestrator          ░░░░░░░░░░ not started
[7] Expansion             ░░░░░░░░░░ not started
```

**Phase 0 is deliberately zero-attack-capability.** No nmap, nuclei, or sqlmap yet — just `curl` as a bridge tool for testing. The principle: **fences first, weapons later.** No offensive tool gets installed before this safety layer is proven by automated tests.

**Phase 0.5 makes that same safety layer installable as a plugin**, so it runs from any project directory instead of only from inside this repo checkout. It changes nothing about the enforcement logic — only *where* it reads code from and writes state to.

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
    │ passes through omop-exec
    ▼
┌─────────────────────────┐   target outside scope.yaml?
│  omop-exec               │──────────────► DENY + audit log
│  (choke point)           │
│  scope → safety → audit  │
└─────────────────────────┘
    │ ALLOW
    ▼
┌─────────────────────────┐
│  docker exec             │  tool runs in an isolated container
│  (omop-<engagement>)     │
└─────────────────────────┘
```

- **Deny-by-default** — a target not explicitly listed in `in_scope` is rejected. When in doubt, rejected.
- **Fail-closed** — a broken `scope.yaml` or no active engagement means everything is rejected.
- **`out_of_scope` wins** over `in_scope` — explicit exclusions always take priority.
- **Two independent layers** — the hook stops the agent from *avoiding* `omop-exec`; `omop-exec` itself does the real check.
- **Full audit trail** — every decision (ALLOW/DENY) is logged: timestamp, target, tool, reason, authorization.

All of this is verified by [`test/acceptance.test.mjs`](test/acceptance.test.mjs) and [`test/plugin-e2e.test.mjs`](test/plugin-e2e.test.mjs) — not a claim, there's proof:

```bash
bun test   # 103 pass · 1 skip (Docker smoke, needs a live container) · 0 fail
```

## Install as a Claude Code plugin

```
/plugin marketplace add tuktukerz/boundhound
/plugin install boundhound@tuktukerz-marketplace
```

Once installed, `/engagement`, `/mode`, and the scope-guard hook work from **any** project directory — you no longer need to be inside this repo checkout. Engagement state (scope files, `.active`, audit logs) lives under the plugin's own data directory (`${CLAUDE_PLUGIN_DATA}`), so it persists across plugin updates instead of being wiped when the plugin's code is refreshed.

## Run from a clone (dev mode)

The alternative to installing as a plugin: clone the repo and run everything locally, with state kept inside the checkout (`$CLAUDE_PROJECT_DIR`) instead of `${CLAUDE_PLUGIN_DATA}`. Useful for developing Boundhound itself.

```bash
bun install
bun test                        # 103 pass / 1 skip

bin/omop-container up smoke     # start the tool container
node bin/omop-engagement.mjs acme   # scaffold a new engagement -> fill in scope.yaml
node bin/omop-exec.mjs curl --target api.acme.io -- -I   # run a tool through the choke point
```

## Structure

```
.claude-plugin/
  plugin.json              plugin manifest (skills/commands/hooks entry points)
  marketplace.json         self-hosted marketplace so the repo is /plugin-installable
.claude/
  skills/pentest-mode/     active skill (harvested from OmOP, tuned to our system)
  commands/                /engagement, /mode
  settings.json            PreToolUse hook registration (dev/project mode)
bin/
  omop-exec.mjs            choke point: scope + safety + audit -> docker exec
  omop-engagement.mjs      scaffold a new engagement
  omop-container           Docker container lifecycle
hooks/
  scope-guard.mjs          blocks omop-exec bypass attempts
  hooks.json               PreToolUse hook registration (plugin mode, ${CLAUDE_PLUGIN_ROOT})
src/
  paths.mjs                code root vs data root resolution (plugin vs local-project)
  scope/                   parser + matcher (deny-by-default) + fail-closed resolver
  safety/                  blocks destructive/DoS actions
  catalog/                 tools-catalog.json loader (ToolEntry schema, OmOP-style)
  guard/                   command classification, anti-bypass
  audit/                   JSONL audit log
docker/Dockerfile          minimal image — bridge tool only
skills-library/            archived OmOP skills (reference, not yet active)
docs/
  ARCHITECTURE.md          big-picture map & 8 phases
  specs/, plans/           spec & implementation plan per phase
```

## Design principles

1. **Safety before capability.** Every new capability phase (recon, exploit, etc.) is built on a foundation that has already passed its tests — not the other way around.
2. **Harvest, don't fork.** OmOP's skills (250 `SKILL.md` files) are taken as raw material, kept in `skills-library/`, and promoted to active skills one at a time while being tuned — not imported wholesale.
3. **Enforcement, not instruction.** When something must hold true, it's enforced by code/hooks — not just written into agent instructions.
4. **Every task = TDD + adversarial review.** Built via subagent-driven development: each module is written test-first, reviewed by an independent subagent, and every finding (including real bugs — a guard bypass, a fail-open hook, a dead `import.meta.main` check on Node) is closed with a regression test before moving on.

## Roadmap

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full map of all 8 phases, design decisions, and the reasoning behind each architectural choice.

---

*Built iteratively: brainstorming → grilling → spec → plan → subagent-driven implementation, each step reviewed before moving on.*
