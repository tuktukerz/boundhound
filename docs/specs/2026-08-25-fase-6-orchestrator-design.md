# Design Spec — Phase 6: Orchestrator (`/fullscan`)

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0–5 merged.
**Guiding principle:** one entry point (`/fullscan` / `bh-fullscan`) that runs the WHOLE engagement autonomously — recon → enumeration → exploitation → findings → report — with **every tool invocation still going through the `bh-exec` choke point** (scope + safety + audit + container). The orchestrator adds no new capability and no new attack surface; it sequences the already-bounded tools and the already-built synthesizers. This is the autonomous-pentest payoff, and it is safe by construction because it cannot do anything a manual operator couldn't already do through `bh-exec`.

---

## 1. Goal & Non-Goals

### Goal
A staged pipeline driver that, for the active in-scope engagement, runs the phase chain end to end and produces `report.md`, deriving each stage's targets deterministically from the prior stages' maps, executing every tool step through `bh-exec`, and rebuilding the maps between stages. Split into: a **pure planner** (`targetsForStage`), an **injectable driver** (`runFullscan`), a **`bh-fullscan` CLI**, and a **`pentest-workflow` skill + `/fullscan` command**.

### Non-Goals (STRICT)
- ❌ No new attack tool, no catalog/Docker/safety-check/command-builder/bh-exec change. `bh-fullscan` orchestrates the existing CLIs; it never bypasses `bh-exec` and never runs a tool directly.
- ❌ The orchestrator NEVER escalates or relaxes any bound — every tool step is the same bounded invocation the per-phase skills already use (recon httpx/nmap flags, enum ffuf/nuclei flags, exploit sqlmap bounded flags). Out-of-scope/denied steps are skipped/denied exactly as `bh-exec` decides.
- ❌ `bh-fullscan` fail-closes on a broken/unauthorized scope (no active engagement / bad scope → refuse), consistent with deny-by-default.
- ❌ Not parallel tool execution in v1 — sequential, deterministic ordering (simpler, auditable). Parallelism is a Phase-7 expansion.

### Definition of Done
- `src/orchestrate/fullscan.mjs`: `targetsForStage(stage, {reconMap, enumMap}, scope) -> [{tool,target,flags}]` (pure, in-scope-filtered, deterministic) + `runFullscan({runner, synth, loadMaps, scope, log}, opts) -> summary` (staged driver, runner/synth/loadMaps injected).
- `bin/bh-fullscan.mjs`: wires the real runner (spawns `node bin/bh-exec.mjs <tool> --target <t> --data-dir <d> -- <flags>` capturing stdout to the phase's output file) + the real synth (spawns `bh-recon-map`/`bh-enum-map`/`bh-exploit-map`/`bh-findings`/`bh-report`); fail-closed on no active engagement / broken scope.
- `pentest-workflow` skill + `/fullscan` command.
- **REAL e2e**: `bh-fullscan` against a live nginx target → runs the real recon+enum chain through `bh-exec` → produces a real `findings.json` + `report.md`; assert the report covers the discovered surface; assert an out-of-scope target is never scanned (the driver only plans in-scope targets, AND `bh-exec` denies any that slip). Controller-run.
- All existing tests green; README updated in this phase's PR.

---

## 2. Core: staged pipeline (`src/orchestrate/fullscan.mjs`, pure planner + injectable driver)

### 2.1 The stages (fixed, ordered)
```
recon:subfinder → recon:httpx → recon:nmap → enum:nuclei → enum:ffuf → exploit:sqlmap → findings → report
```
(A separate `/verify` re-confirmation pass remains available; v1 fullscan does a single forward pass. Documented.)

### 2.2 `targetsForStage(stage, maps, scope) -> steps` (PURE)
Given the CURRENT maps + the parsed scope, derive the tool steps for that stage. Every derived target is passed through the existing `matchTarget(target, scope)` and only ALLOWed targets are included (defense-in-depth: `bh-exec` re-checks anyway, but the planner must never plan a known out-of-scope target). Deterministic ordering.
- `recon:subfinder` → for each `scope.in_scope.domains` root: `{tool:"subfinder", target:<domain>, flags:["-silent","-json"]}`.
- `recon:httpx` → for each in-scope host = the roots + `reconMap.subdomains` that clear scope: `{tool:"httpx", target:"http://<host>", flags:["-silent","-json","-td","-title","-sc"]}`.
- `recon:nmap` → for each host in `reconMap.hosts`/discovered in-scope hosts: `{tool:"nmap", target:<host>, flags:["-sT","-Pn","-T3","-p","80,443,22,8080,8443","-oG","-"]}`.
- `enum:nuclei` → for each `reconMap.http_services[].url` (live) that clears scope: `{tool:"nuclei", target:<url>, flags:["-silent","-jsonl","-disable-update-check","-severity","info,low,medium,high,critical","-c","25","-rl","150"]}`.
- `enum:ffuf` → for each live http service url: `{tool:"ffuf", target:"<url>/FUZZ", flags:["-w","/usr/share/boundhound/wordlists/common.txt","-mc","200,204,301,302,401,403","-t","40","-o","/dev/stdout","-of","json","-s"]}`.
- `exploit:sqlmap` → for each `reconMap.http_services[].url` (or enum content url) that CONTAINS a query parameter (`?k=v`): `{tool:"sqlmap", target:<url>, flags:["--batch","--level","1","--risk","1","--dbs"]}` (`-p` derived from the first param). Hosts with no param URL → NO sqlmap step (correct: nothing to test).
- `findings` / `report` → not tool steps; the driver runs `bh-findings` / `bh-report` (via `synth`).

All flags above are ALREADY the declared/cataloged bounded flags for each tool — the planner introduces nothing new.

### 2.3 `runFullscan({ runner, synth, loadMaps, scope, log }, { stages, exploit }) -> summary` (driver)
- `runner({tool, target, flags, stage}) -> void` — executes one tool step (production: bh-exec → capture stdout → append to the stage's output file). Injectable (mock in tests).
- `synth(kind) -> void` — runs a synthesizer CLI (`recon-map`/`enum-map`/`exploit-map`/`findings`/`report`). Injectable.
- `loadMaps() -> { reconMap, enumMap }` — reads the current maps from disk (injectable; returns whatever exists).
- For each stage in order: `steps = targetsForStage(stage, loadMaps(), scope)`; run each step via `runner`; then `synth` the stage's map (recon stages → `synth("recon-map")`; enum stages → `synth("enum-map")`; exploit → `synth("exploit-map")`). After the tool stages: `synth("findings")` then `synth("report")`.
- The `exploit` stage is gated by an `opts.exploit !== false` flag AND the presence of param URLs (default on; a `--no-exploit` CLI flag disables it — safety-conservative default is documented; exploitation only runs bounded sqlmap and only on in-scope param URLs).
- Returns a `summary`: per-stage step counts, tools run, and the final report path. `log(line)` narrates progress. NEVER throws on an empty stage (no targets → skip, log it).

---

## 3. `bin/bh-fullscan.mjs` (CLI)
Mirrors the other bins (`--data-dir`, `process.argv[1]` main-detection, `dataRoot()`, fail-closed code 3 on no active engagement / broken scope via `loadActiveConfig`). Wires:
- `runner` = spawn `node <root>/bin/bh-exec.mjs <tool> --target <target> --data-dir <dDir> -- <flags>`, capture stdout, write/append to the stage's output file under `engagements/<active>/output/<phase>/…` (matching where each map-builder reads from). A DENY (exit 2) from bh-exec is logged and skipped, not fatal (an out-of-scope or safety-denied step doesn't abort the scan).
- `synth` = spawn the corresponding `node <root>/bin/bh-<kind>.mjs --data-dir <dDir>`.
- `loadMaps` = read the recon/enum map JSON from disk.
- Flags: `--no-exploit` (skip the sqlmap stage). Writes nothing new beyond what the sub-CLIs already write; the final deliverable is `output/report/report.md`.

---

## 4. `pentest-workflow` skill + `/fullscan` command
Self-authored, no external refs. `.claude/skills/pentest-workflow/SKILL.md`:
1. Require an active, authorized, in-scope engagement (else guide the operator to `/engagement`).
2. Explain that `/fullscan` runs the entire chain autonomously and that **every tool step still passes through `bh-exec`** (scope + safety + audit + container) — the orchestrator cannot exceed any per-phase bound, and a denied step is skipped, not forced.
3. Run `bh-fullscan` (plugin/dev-mode invocation) → the final `report.md`. Note `--no-exploit` for a non-intrusive recon+enum+report run.
4. Summarize the resulting report. Reference the individual `/recon`,`/enum`,`/exploit`,`/verify`,`/report` commands for step-by-step control.
`.claude/commands/fullscan.md` (`/fullscan`) mirrors the other commands. `tools:` lists the orchestrated tools; `phase: ["orchestrator"]`.

---

## 5. Safety analysis (why an orchestrator adds no risk)
| Concern | Bound |
|---|---|
| Autonomous multi-tool run | every step is `bh-exec <tool> --target … -- <bounded flags>` — scope-checked, safety-capped, audited, in-container; identical to manual per-phase runs |
| Target selection | planner only derives IN-SCOPE targets (matchTarget-filtered); bh-exec re-checks each; a denied step is skipped |
| Exploitation in the loop | only bounded sqlmap on in-scope param URLs; the Phase-3 double-layer (block_destructive + catalog allowlist) still denies every weaponizing flag; `--no-exploit` for a fully non-intrusive run |
| Fail-closed | `bh-fullscan` refuses to run without an active, valid, authorized scope |
| No bypass | `bh-fullscan` NEVER runs a tool directly — always via `bh-exec`; the guard hook still denies direct tool calls |

The orchestrator is a sequencer over already-proven-safe primitives; it cannot produce an action that a manual `bh-exec` sequence couldn't.

---

## 6. Acceptance criteria
| # | Test | Expect |
|---|---|---|
| O1 | `targetsForStage` per stage over map fixtures: derives the right in-scope steps with the right bounded flags; OUT-OF-SCOPE discovered targets are excluded (matchTarget); no-param-URL → no sqlmap step; empty maps → empty steps (no throw) | correct, in-scope-only planning |
| O2 | `runFullscan` with a MOCK runner+synth+loadMaps: runs stages in the fixed order, calls runner per derived step, calls the right synth per stage, does findings+report last; a denied/failing step is skipped not fatal; empty stage skipped; `--no-exploit`/`exploit:false` omits the sqlmap stage; returns a correct summary | correct staged orchestration |
| O3 | `bh-fullscan` CLI: fail-closed code 3 on no active engagement / broken scope (no runs); wires real runner/synth (mock the spawn in a unit test OR assert the constructed commands) | fail-closed + correct wiring |
| O4 | full `bun test` green | 478+ pass |
| E2E | **REAL:** live nginx target + `bh:base` engagement, in-scope. Run real `bh-fullscan --data-dir <tmp>` → assert the real chain ran (recon http_service for nginx, an nmap open-port, an enum nuclei/ffuf result), a real `findings.json` and `output/report/report.md` are produced covering the target, and NO out-of-scope host was ever contacted (audit log shows only in-scope ALLOWs + the expected DENYs). Controller-run. | real autonomous scan end-to-end |

---

## 7. Deferred / notes
- Parallel tool execution, retry/backoff, per-stage budgets, resumable state → Phase 7 expansion.
- A verify re-confirmation pass inside fullscan (currently `/verify` is separate) → optional future `--verify` flag.
- The tracked `now`-non-function + `fase-*` filename follow-ups remain deferred.
