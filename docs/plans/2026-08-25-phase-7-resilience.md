# Phase 7 — Resilient Autonomous Scanning: Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Make `bh-fullscan` production-grade for long real engagements — resumable run state (`--resume`), bounded retry/backoff on transient (non-DENY) failures, and a hard per-run/per-stage step budget — all as pure/injectable orchestration over the existing bounded tools, with NO new attack surface and every step still through `bh-exec`. Proven by a REAL e2e (resume skips done work; a transient failure is retried).

**Spec:** `docs/specs/2026-08-25-phase-7-resilience-design.md`

## Global Constraints
- NO new attack tool; NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, `bin/bh-exec.mjs`. The orchestrator NEVER runs a tool directly — always via `bh-exec`, byte-identical bounded command.
- **Backward compatibility is mandatory.** All new `runFullscan`/CLI options are optional and DEFAULT to today's behavior: no state file, `maxRetries:0`, no budget. A runner returning `undefined` → treated `ok`; a runner that throws → treated `transient` (matches today's skip-not-fatal). Existing Phase-6 tests for `src/orchestrate/fullscan.mjs` and `bin/bh-fullscan.mjs` MUST stay green unchanged (adapt them only if a signature genuinely requires it, and preserve their asserted behavior).
- **Retry never relaxes a bound.** Only NON-DENY transient failures retry; a `bh-exec` DENY (exit 2) is final — never retried, marked done, skipped-not-fatal. The retried command is identical.
- **Budgets only reduce work**, never expand it. **Resume** touches only one JSON file under `engagements/<active>/output/`.
- Pure run-state model (no I/O, never throws); driver's `loadState`/`saveState`/`sleep`/`runner`/`synth`/`loadMaps` injectable. Sequential/deterministic preserved (no parallelism). No time/random in the pure model. Node ESM `.mjs`, `bun test`, no build step. English only.

---

### Task 1: run-state model — `src/orchestrate/run-state.mjs` (pure)

**Files:** Create `src/orchestrate/run-state.mjs`, `src/orchestrate/run-state.test.mjs`.

**Interfaces produced (spec §2):** `stepKey({stage,tool,target}) -> string` (stable, deterministic, no time/random); `emptyState() -> {version,done:{}}`; `isDone(state,key) -> bool` (false on missing/garbage); `markDone(state,key) -> state` (pure, returns new state); `parseState(text) -> state` and `serializeState(state) -> text` (tolerant: malformed → emptyState, never throw).

- [ ] Write failing tests: `stepKey` deterministic + distinct for distinct tuples + stable across calls; `isDone`/`markDone` correct (markDone is non-mutating); `parseState` on `""`/`"{"`/`"null"`/wrong-shape → `emptyState()` (no throw); serialize→parse round-trips; `isDone` on `emptyState()` → false. Run → RED.
- [ ] Implement the pure model (no I/O, never throws, no Date/Math.random).
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(orchestrator): pure run-state model for resumable scans`

---

### Task 2: driver extension — resume + retry + budget in `runFullscan`

**Files:** Modify `src/orchestrate/fullscan.mjs`; extend `src/orchestrate/fullscan.test.mjs`.

**Consumes:** Task 1.

**Interfaces produced (spec §3):** `runFullscan({runner, synth, loadMaps, scope, log, loadState, saveState, sleep}, {exploit, resume, retry, budget}) -> summary`, all new fields OPTIONAL. Runner outcome classified `ok|denied|transient` (undefined→ok, throw→transient, `{status}`→that status). Resume: load once, skip `isDone` steps (don't call runner), `markDone`+`saveState` per completed unit (a DENY is settled → also marked done). Retry: transient retried up to `retry.maxRetries` with `await sleep(retry.backoff(attempt))`; denied/ok never retried; `maxRetries:0` = today. Budget: `maxSteps`/`maxStepsPerStage` stop work at the ceiling; findings+report still run. Summary gains `resumedSkipped`, `retried`, `budgetStopped`.

- [ ] Read the current `src/orchestrate/fullscan.mjs` + its test first; preserve every existing behavior/assertion.
- [ ] Write failing tests (S2/S3/S4): resume skips pre-seeded-done steps + saveState per unit + `resumedSkipped` count; retry retries transient-then-ok K times (injected sleep counted) + never retries denied (marked done) + `maxRetries:0` reproduces current behavior; budget maxSteps/maxStepsPerStage stop at ceiling + findings+report still run + `budgetStopped` set. Confirm existing Phase-6 O2 tests still pass with defaults. Run → RED.
- [ ] Implement (injectable, sequential, deterministic; defaults = today).
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(orchestrator): resumable state + bounded retry + run budget in runFullscan`

---

### Task 3: `bin/bh-fullscan.mjs` CLI wiring

**Files:** Modify `bin/bh-fullscan.mjs`; extend `bin/bh-fullscan.test.mjs`.

**Consumes:** Tasks 1–2.

**Interfaces produced (spec §4):** new flags `--resume`, `--max-retries N` (default 0), `--max-steps N`, `--max-steps-per-stage N`. Real `loadState`/`saveState` at `engagements/<active>/output/fullscan-state.json` (tolerant read → emptyState; simple write). Real `sleep` (setTimeout-based) + bounded backoff `min(base*2^attempt, cap)` (NO random). Real runner now returns `{status}` (exit 0 → ok, exit 2 → denied, else → transient) while keeping the DENY log-and-skip. Fail-closed code 3 unchanged; per-host output files + synth chain unchanged.

- [ ] Read current `bin/bh-fullscan.mjs` + its test first; preserve fail-closed + output-wiring behavior.
- [ ] Write failing tests (S5): flags parsed + threaded into `runFullscan`; with a stubbed spawn, a run writes the state file, and a second `--resume` run skips already-done steps (asserts no re-spawn for done steps); `--max-steps 1` stops after one step; runner maps exit 0/2/other → ok/denied/transient; existing fail-closed (no active engagement / broken scope → code 3, zero spawns) still holds. Run → RED.
- [ ] Implement. Focused tests → GREEN. Full `bun test` before committing.
- [ ] Commit: `feat(orchestrator): bh-fullscan --resume/--max-retries/--max-steps wiring`

---

### Task 4: `pentest-workflow` skill + `/fullscan` command update

**Files:** Modify `.claude/skills/pentest-workflow/SKILL.md`, `.claude/commands/fullscan.md`; extend `test/workflow-skill.test.mjs`.

**Interfaces produced (spec §5):** document `--resume`, `--max-retries`, `--max-steps`; reiterate retry re-runs the IDENTICAL bounded `bh-exec` command and a DENY is never retried; budgets only reduce work. No external refs; English only.

- [ ] Read current `.claude/skills/pentest-workflow/SKILL.md` + `/fullscan` first.
- [ ] Extend `test/workflow-skill.test.mjs`: assert the skill documents `--resume`/`--max-retries`/`--max-steps`, states retry uses the same bounded command + never retries a DENY, and budgets only cap; NO external refs; NO Indonesian. Run → RED. Author the additions (our words). Run → PASS; FULL `bun test`.
- [ ] Commit: `docs(orchestrator): pentest-workflow documents resume/retry/budget`

---

### Task 5: REAL e2e — resume skips done work + transient retry

**Files:** Create `test/fullscan-resilience-e2e.test.mjs` (mirror `test/fullscan-e2e.test.mjs` harness: docker skip, per-pid `bh-e2eresil` names, prefix sweep, fail-safe afterAll, dotted-FQDN, target seeded in-scope).

**Interfaces produced:** real, offline, deterministic e2e (spec §6 E2E).

- [ ] Write `test/fullscan-resilience-e2e.test.mjs`: live nginx + `bh:base`. (a) Run real `node bin/bh-fullscan.mjs --data-dir <tmp> --no-exploit` to completion → assert `fullscan-state.json` exists with done units + `report.md` produced. Then run again with `--resume` → assert the second run's NEW audit entries do NOT include duplicate ALLOWs for already-done steps (i.e. done stages were skipped) and `report.md` still valid. (b) Resilience of retry: drive a scenario where one step transiently fails once then succeeds (e.g. via a wrapper/first-run condition you can control deterministically) and assert `--max-retries 1` completes the scan — OR, if a real transient can't be reliably forced in-container, assert the retry path at the CLI level against a controlled stubbed runner and document that the real e2e covers resume for-real while retry is covered by the S3 unit + a controlled CLI test. Prefer a real forced-transient if feasible; do NOT fake. Fail-safe teardown.
- [ ] Controller RUNS it for real (`bun test test/fullscan-resilience-e2e.test.mjs`, docker up, generous timeout). Capture evidence (state file + audit deltas). If blocked, report specifics — do NOT fake.
- [ ] FULL `bun test`.
- [ ] Commit: `test(orchestrator): real e2e — resume skips done work + retry completes`

---

### Task 6: README + plugin.json

**Files:** Modify `README.md`, `.claude-plugin/plugin.json`.

- [ ] README: status/roadmap → Phase 7 done; add a **Resilience** note under Orchestration (`--resume` continues an interrupted scan; `--max-retries` retries transient tool failures with the SAME bounded command, never a DENY; `--max-steps`/`--max-steps-per-stage` cap a run; state file `output/fullscan-state.json`; real e2e proves resume). Update `bun test` count; add `src/orchestrate/run-state.mjs` to Structure. plugin.json description → Phase 7. No external refs, no residual "Fase".
- [ ] FULL `bun test`.
- [ ] Commit: `docs(orchestrator): README Phase 7 resilience capability + plugin description`

---

## Self-Review
- Spec coverage: §2→T1, §3→T2, §4→T3, §5→T4, §6 e2e→T5, README→T6. ✅
- No new tool/catalog/Docker/safety/bh-exec change; every step via bh-exec (identical bounded command); retry only transient/non-DENY; budgets only reduce; resume = one JSON file; pure model never-throws/no-time-random; driver injectable; backward-compatible defaults; sequential/deterministic preserved; real resume e2e.
- Ordering: T1→T2 (driver consumes model)→T3 (CLI consumes driver)→T4 (skill)→T5 (e2e)→T6 (README). T2 & T3 edit existing merged files — preserve all Phase-6 behavior.
