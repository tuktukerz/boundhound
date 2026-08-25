# Boundhound — Architecture & Roadmap

**An autonomous pentest agent built natively on Claude Code.**
An original project — the orchestrator, the safety layer, and the skill library are all written from scratch.

> Status: **Phases 0–6 merged.** The safety foundation, plugin packaging, the full tool chain (recon → enumeration → exploitation → verification → reporting), and the autonomous orchestrator (`/fullscan`) are all implemented, tested, and merged to `main`. Phase 7 (Expansion) is next.

---

## 1. Why native Claude Code

Boundhound is built directly on Claude Code primitives. Its core asset is a **library of `SKILL.md` playbooks** — pure markdown, written from scratch, promoted into active skills phase by phase. The orchestrator, the tool runner, and the config layer are all our own.

**Decision:** keep the playbooks as a self-authored skill library, then build the orchestrator and the safety layer on top of Claude Code primitives.

---

## 2. Definition of Success (v1)

> On a single **authorized** target, **one command** runs **recon → enumeration → exploitation → verification → reporting** and produces a **submittable report**, with **zero scope violations**.

Two non-negotiable metrics: **(1)** the output is a genuinely usable report, and **(2)** zero requests leave the authorized scope.

As of Phase 6 this is delivered end to end: `/fullscan` drives the whole chain autonomously, and a real end-to-end test proves an autonomous scan against a live target with no out-of-scope contact.

---

## 3. Mapping to Claude Code primitives

| Pentest-agent concept | Realized with |
|---|---|
| Skill playbooks (recon, enum, exploit, verify, report, workflow) | Skill frontmatter + `.claude/skills/*/SKILL.md` (active) + `skills-library/` (source library) |
| Tool registry | `tools-catalog.json` (`ToolEntry` schema) + `src/command-builder/` |
| Tool execution (subfinder, httpx, nmap, ffuf, nuclei, sqlmap) | `bin/bh-exec.mjs` → `docker exec` into a Linux container (`bh:base`) |
| Tools via MCP (e.g. Burp Suite) | Native Claude Code MCP server — see §7 (planned) |
| Orchestrator (recon → … → report) | `src/orchestrate/fullscan.mjs` + `bin/bh-fullscan.mjs`, driving each phase's CLI |
| `/engagement`, `/fullscan`, per-phase commands | `.claude/commands/*.md` |
| Engagement mode | Skill / command argument (`pentest-mode`, `/mode`) |
| **Scope enforcement** | **`PreToolUse` hook** (`hooks/scope-guard.mjs`) + the `bh-exec` choke point |
| Safety profile (anti-destructive / anti-DoS) | `src/safety/safety-check.mjs`, enforced inside `bh-exec` |
| Verification layer | `src/verify/findings.mjs` + `bin/bh-findings.mjs` + `/verify` |
| Report | `src/report/report.mjs` + `bin/bh-report.mjs` + `/report` |
| Chain of custody / audit | `bh-exec` writes `engagements/<target>/audit.log` |

---

## 4. Locked decisions

| # | Decision |
|---|---|
| Direction | Build it ourselves, native to Claude Code |
| Goal | Learning + real work + portfolio (bar set at "real work") |
| Legal | Authorized engagements + bug bounty + own lab only |
| Platform | Claude Code |
| Tool runtime | Lean custom Docker/Linux image, one persistent container per engagement |
| Bridge | Claude Code on the Mac drives the container via `docker exec` |
| Autonomy | Full-auto **through exploitation**, but always **inside two mandatory guardrails** |
| Guardrail 1 | Hard scope hook, **deny-by-default** |
| Guardrail 2 | Safety profile — blocks destructive/DoS actions by default |
| Scope | `scope.yaml` per engagement |
| Skills | Self-authored library in `skills-library/`, promoted + tuned per phase |
| Models | Mixed per phase (fast models for recon/enum, stronger models for exploit/verify/report/review) |
| Location | New git repo `~/Documents/ian/boundhound` |
| Ordering | **Phase 0 (safety) first**, mandatory |

---

## 5. Phase map

Each phase is a self-contained milestone with its own **spec → plan → implement** cycle, its own real end-to-end test, and its own PR.

| Phase | Name | Milestone output | Status |
|---|---|---|---|
| **0** | **Foundation & Safety** | Scope enforcement + Docker bridge + audit + `/engagement`. Provably cannot touch an out-of-scope target. **Zero attack capability.** | ✅ merged |
| 0.5 | Plugin Packaging | Ships as a Claude Code plugin (`.claude-plugin/`, hooks, marketplace) | ✅ merged |
| 1 | Recon | Structured attack-surface map (subdomains, hosts, ports, tech) via subfinder/httpx/nmap | ✅ merged |
| 2 | Enumeration | Raw findings (nuclei detections, ffuf endpoints) built on the recon map | ✅ merged |
| 3 | Exploitation | Bounded proof-of-vulnerability (sqlmap), full-auto inside the guardrails | ✅ merged |
| 4 | Verification | Every finding re-confirmed; false positives dropped | ✅ merged |
| 5 | Reporting | A professional `report.md` (exec summary, scope, methodology, findings-by-severity + remediation) | ✅ merged |
| 6 | Orchestrator | `/fullscan` chains every phase autonomously, each step still through `bh-exec` | ✅ merged |
| 7 | Expansion | New domains: network/AD, mobile, CTF; an intelligence layer; parallelism/resumability | ⏳ next |

**Principle:** *safety before capability.* Not a single attack tool ships before Phase 0's tests pass, and every later phase keeps every tool step behind the same `bh-exec` choke point.

---

## 6. Repository structure

```
boundhound/
├── .claude-plugin/          # plugin.json + marketplace.json (Phase 0.5 packaging)
├── .claude/
│   ├── commands/            # /engagement, /mode, /recon, /enum, /exploit, /verify, /report, /fullscan
│   └── skills/              # ACTIVE skills, promoted per phase (pentest-recon/enum/exploit/verify/report/workflow/mode)
├── bin/
│   ├── bh-exec.mjs          # build command from catalog → scope + safety → docker exec → audit (the choke point)
│   ├── bh-engagement.mjs    # scaffold an engagement + set active + bring up the container
│   ├── bh-container         # container helper
│   ├── bh-recon-map.mjs     # synthesize recon output → recon-map.json
│   ├── bh-enum-map.mjs      # synthesize enum output → enum-map.json
│   ├── bh-exploit-map.mjs   # synthesize exploit output → exploit-map.json
│   ├── bh-findings.mjs      # consolidate + verify → findings.json
│   ├── bh-report.mjs        # findings.json + scope.yaml → report.md
│   └── bh-fullscan.mjs      # orchestrator CLI: drive the whole chain through bh-exec
├── hooks/
│   └── scope-guard.mjs      # PreToolUse enforcement; denies any direct tool call that bypasses bh-exec
├── src/
│   ├── catalog/             # tools-catalog.json loader (requires fully-anchored value_patterns)
│   ├── command-builder/     # build the command line from ToolEntry.flags
│   ├── scope/               # scope.yaml parsing + matchTarget (deny-by-default)
│   ├── safety/              # safety-check: destructive/DoS bounds
│   ├── guard/               # bh-exec choke-point guard
│   ├── audit/               # audit-log helpers
│   ├── recon/ enum/ exploit/  # per-phase map synthesizers
│   ├── verify/ report/      # findings consolidation + report rendering
│   ├── orchestrate/         # fullscan planner + staged driver
│   └── paths.mjs            # codeRoot / dataRoot split (plugin data dir)
├── tools-catalog.json       # declarative tool registry (ToolEntry schema)
├── docker/Dockerfile        # lean multi-stage base; tools added per phase (image bh:base)
├── skills-library/          # self-authored skill library (source; not loaded directly)
├── engagements/
│   ├── .active              # pointer to the active engagement
│   └── <target>/
│       ├── scope.yaml       # engagement config: mode + scope + safety constraints
│       ├── audit.log        # chain of custody for every command
│       └── output/          # per-phase results (recon/enum/exploit/verify/report)
├── test/                    # unit + real docker-backed e2e tests (bun test)
└── docs/
    ├── ARCHITECTURE.md      # this document
    ├── specs/               # detailed per-phase design specs
    └── plans/               # per-phase implementation plans
```

---

## 7. MCP integration (e.g. Burp Suite) — planned

Claude Code supports native MCP servers, so adding a tool via MCP is on-pattern. **Burp Suite** ships an official MCP server that fits web / bug-bounty work well (Proxy, Repeater, Scanner). Intended placement: a later expansion phase, not the core chain.

Important caveats when it is adopted:
- It needs Burp running (Burp **Pro** for active scan; Community is limited). Burp runs on the **host**, not inside the tool container.
- **Safety:** our scope-guard hook only sees Bash commands — it does **not** see each request Burp sends. So a Burp scope must **also** be set in Burp's own Target Scope, and Burp MCP calls are treated as a separate choke point.

This is deferred to Phase 7 (Expansion); it is not part of the merged core chain.
