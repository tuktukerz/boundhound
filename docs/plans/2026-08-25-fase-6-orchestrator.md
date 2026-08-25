# Phase 6 — Orchestrator: Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** A staged autonomous-scan pipeline (`bh-fullscan` / `/fullscan`) that runs recon→enum→exploit→findings→report end to end, deriving each stage's targets deterministically + in-scope-filtered, executing every tool step through `bh-exec`, proven by a REAL e2e — orchestrating the existing bounded tools/CLIs with no new attack surface.

**Spec:** `docs/specs/2026-08-25-fase-6-orchestrator-design.md`

## Global Constraints
- NO new attack tool; NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, `bin/bh-exec.mjs`. The orchestrator NEVER runs a tool directly — always via `bh-exec`.
- The planner derives ONLY in-scope targets (via the existing `matchTarget`); every step uses the SAME bounded flags the per-phase skills already use — no new/wider flags, no escalation.
- `bh-fullscan` fail-closes on no active engagement / broken scope. A `bh-exec` DENY on a step is skipped, not fatal.
- Pure planner (no I/O, never throws); driver's runner/synth/loadMaps injectable for tests. Node ESM `.mjs`, `bun test`, no build step. English only.

---

### Task 1: fullscan module — `targetsForStage` (pure) + `runFullscan` (driver)

**Files:** Create `src/orchestrate/fullscan.mjs`, `src/orchestrate/fullscan.test.mjs`, fixtures under `test/fixtures/orchestrate/` (a `recon-map.json` with subdomains/http_services/hosts incl. an in-scope + an out-of-scope discovered subdomain + a param URL, an `enum-map.json`, and a parsed `scope` object).

**Interfaces produced (spec §2):**
- `targetsForStage(stage, {reconMap, enumMap}, scope) -> [{tool,target,flags}]` — pure, per spec §2.2; every target `matchTarget`-filtered to in-scope; deterministic order; empty/missing maps → `[]` (no throw). Stages: `recon:subfinder`, `recon:httpx`, `recon:nmap`, `enum:nuclei`, `enum:ffuf`, `exploit:sqlmap`.
- `runFullscan({runner, synth, loadMaps, scope, log}, {exploit} = {}) -> summary` — staged driver per spec §2.3: for each stage in the fixed order, derive steps from `loadMaps()`, run each via `runner`, then `synth` the stage's map; after tool stages, `synth("findings")` then `synth("report")`. `exploit:false` (or `--no-exploit`) omits the sqlmap stage. Empty stage skipped + logged. A runner that returns/throws a "denied" result is skipped, not fatal. Returns `{stages:[{stage,steps}], reportGenerated, ...}`.

- [ ] Read `src/scope/scope-matcher.mjs` (`matchTarget`, `normalizeTarget`) + the map shapes (`src/recon/recon-map.mjs`, `src/enum/enum-map.mjs`) first.
- [ ] Write fixtures + failing tests: O1 (each stage → correct in-scope steps + correct bounded flags; an OUT-OF-SCOPE discovered subdomain is EXCLUDED; a URL with no `?param` → no sqlmap step; a URL with `?id=1` → sqlmap step with `-p id`; empty maps → `[]` no throw). O2 (runFullscan with mock runner/synth/loadMaps: fixed stage order, runner called per step, right synth per stage, findings+report last, denied step skipped-not-fatal, empty stage skipped, `exploit:false` omits sqlmap, correct summary). Run → RED.
- [ ] Implement pure planner + injectable driver.
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(orchestrator): fullscan planner + staged driver`

---

### Task 2: `bin/bh-fullscan.mjs` CLI

**Files:** Create `bin/bh-fullscan.mjs`, `bin/bh-fullscan.test.mjs`.

**Consumes:** Task 1 module.

**Interfaces produced (spec §3):** CLI mirrors the other bins (`--data-dir`, `process.argv[1]`, `dataRoot()`, fail-closed code 3 on no active engagement / broken scope via `loadActiveConfig`). Wires: `runner` = spawn `node <root>/bin/bh-exec.mjs <tool> --target <t> --data-dir <d> -- <flags>`, capture stdout → the stage's output file (recon → `output/recon/…`, enum → `output/enum/…`, exploit → `output/exploit/…`, matching where each map-builder reads); a bh-exec DENY (exit 2) is logged + skipped. `synth` = spawn `node <root>/bin/bh-<kind>.mjs --data-dir <d>`. `loadMaps` = read the recon/enum map JSON. `--no-exploit` flag.

- [ ] Read `bin/bh-report.mjs` (fail-closed + spawn conventions) + `bin/bh-exec.mjs` (its CLI arg shape) first.
- [ ] Write failing tests: no active engagement / broken scope → code 3, no runs (assert via a stubbed runner/synth that records zero calls, or by asserting the early return). A valid engagement with a small seeded recon-map + a STUBBED spawn (inject a fake `spawn`/`runner` so the test doesn't actually run docker) → assert the constructed bh-exec commands are correct (right tool/target/flags/output path) and stages run in order; `--no-exploit` omits sqlmap. (Design `bh-fullscan.mjs` so its runner/synth/loadMaps are injectable in `runFullscan` and the CLI's `isMain` builds the real ones — mirror how other bins keep `runX` testable.) Run → RED.
- [ ] Implement. Focused tests → GREEN. Full `bun test` before committing.
- [ ] Commit: `feat(orchestrator): bh-fullscan CLI — staged bh-exec + synth chain`

---

### Task 3: `pentest-workflow` skill + `/fullscan` command

**Files:** Create `.claude/skills/pentest-workflow/SKILL.md`, `.claude/commands/fullscan.md`. Create `test/workflow-skill.test.mjs`.

**Interfaces produced (spec §4):** self-authored orchestrator skill; runs `bh-fullscan`; `/fullscan`.

- [ ] Read `.claude/skills/pentest-report/SKILL.md` for style. Read `bin/bh-fullscan.mjs` for the invocation.
- [ ] Write `test/workflow-skill.test.mjs`: frontmatter (`name: pentest-workflow`, description w/ `Triggers:`, `phase` includes `"orchestrator"`, `tools` lists the orchestrated tools); `/fullscan` command with `<command-instruction>`; asserts the skill invokes `bh-fullscan.mjs` (plugin/dev-mode form) and states that every tool step still goes through bh-exec (scope+safety+audit+container) and a denied step is skipped not forced; mentions `--no-exploit`; NO external refs; NO residual Indonesian.
- [ ] Run → FAIL. Author the skill + command (our words). Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(orchestrator): pentest-workflow skill + /fullscan command`

---

### Task 4: REAL e2e — autonomous scan vs a live target

**Files:** Create `test/fullscan-e2e.test.mjs`. Reuse `test/fixtures/enum/nginx-detect.yaml` if a nuclei template is needed (or rely on default recon/enum tools).

**Interfaces produced:** real, offline, deterministic e2e (spec §6 E2E). Mirror `test/enum-e2e.test.mjs` (docker skip, unique per-pid names prefix `bh-e2efullscan`, prefix-sweep, fail-safe afterAll, dotted-FQDN).

- [ ] Write `test/fullscan-e2e.test.mjs`: docker available (else skip): live nginx target + `bh:base` engagement container on a network; a temp `--data-dir` engagement with the target's dotted-FQDN in-scope (`*.` if needed for the derived hosts). Run REAL `node bin/bh-fullscan.mjs --data-dir <tmp> --no-exploit` (—no-exploit keeps it fast/offline; nginx has no SQLi anyway). Assert: a real `output/recon/recon-map.json` (or the raw outputs) shows the nginx http-service + an nmap open port; a real `output/report/report.md` is produced covering the target; the `audit.log` shows in-scope ALLOWs and NO out-of-scope contact. (subfinder needs internet → the in-scope target is given directly via a host/CIDR so recon can proceed from httpx/nmap without live subdomain discovery; document this — the e2e seeds the target host directly rather than relying on subfinder.) Fail-safe teardown.
- [ ] Controller RUNS it for real (`bun test test/fullscan-e2e.test.mjs`, docker up; allow a generous timeout — multiple sequential tool runs). Capture the produced `report.md`. If blocked, report specifics — do NOT fake.
- [ ] FULL `bun test`.
- [ ] Commit: `test(orchestrator): real e2e — bh-fullscan autonomous scan vs live target`

---

### Task 5: README + plugin.json

**Files:** Modify `README.md`, `.claude-plugin/plugin.json`.

- [ ] README: status/roadmap → Phase 6 done; add an **Orchestration (`/fullscan`)** section (one command runs the whole chain recon→enum→exploit→findings→report; every tool step still through the enforced bh-exec choke point; in-scope-only target derivation; `--no-exploit` for a non-intrusive run; fail-closes on a broken scope; real e2e proves an autonomous scan). Update `bun test` count; Structure paths (`src/orchestrate/`, `bin/bh-fullscan.mjs`, `.claude/skills/pentest-workflow/`, `/fullscan`). plugin.json description → Phase 6. No external refs, no residual "Fase".
- [ ] FULL `bun test`.
- [ ] Commit: `docs(orchestrator): README Phase 6 fullscan capability + plugin description`

---

## Self-Review
- Spec coverage: §2→T1, §3→T2, §4→T3, §6 e2e→T4, README→T5. ✅
- No new tool/catalog/Docker/safety change; every step via bh-exec; planner in-scope-only + never-throws; driver injectable; fail-closed CLI; real autonomous-scan e2e.
