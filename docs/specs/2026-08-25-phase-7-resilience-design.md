# Design Spec — Phase 7: Resilient Autonomous Scanning

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0–6 merged.
**Guiding principle:** make the Phase-6 orchestrator (`/fullscan` / `bh-fullscan`) *production-grade* for real, long-running engagements — a scan that survives interruptions and transient tool failures, and that runs under a hard, auditable ceiling — **without adding any new tool, capability, or attack surface**. Every tool step still goes through the `bh-exec` choke point exactly as before; this phase only makes the *sequencing* around those steps resilient and bounded. Execution stays sequential and deterministic (Phase 6 deliberately chose sequential for auditability; parallelism remains deferred).

---

## 1. Goal & Non-Goals

### Goal
Three orchestration improvements layered onto `runFullscan`, all injectable/testable and all pure-or-bounded:
1. **Resumable run state** — the driver records each completed unit (stage + step) to a state file; a `--resume` run skips units already done, so an interrupted multi-hour scan continues instead of restarting.
2. **Bounded retry/backoff** — a transient runner failure (a non-zero exit that is **not** a `bh-exec` DENY) is retried up to a small cap with a bounded backoff schedule; a **DENY (exit 2) is never retried** (still skipped-not-fatal), and a success is never retried.
3. **Run budget** — an optional hard ceiling on the number of tool steps (per run, and optionally per stage); once reached, no further steps are planned/run (logged). This is a safety-*positive* bound on autonomous action.

### Non-Goals (STRICT)
- ❌ No new attack tool, no catalog/Docker/safety-check/command-builder/bh-exec change. This phase orchestrates the existing bounded tools; it never bypasses `bh-exec`, never runs a tool directly, and never relaxes a bound.
- ❌ Retry NEVER relaxes a bound or changes a command — it re-runs the identical bounded `bh-exec` invocation. A DENY is a correct, final decision and is never retried. Retry only applies to transient/non-DENY failures.
- ❌ Not parallel execution — v1 stays sequential/deterministic (parallelism trades away the clean audit ordering and is deferred to a later phase).
- ❌ No new network capability, no new external dependency, no new engagement side effects beyond the single state file under the engagement's own `output/`.
- ❌ Budgets only *stop* work early; they never expand it.

### Definition of Done
- `src/orchestrate/run-state.mjs` (pure): a deterministic state model — `stepKey({stage,tool,target}) -> string`, `isDone(state, key) -> bool`, `markDone(state, key) -> state`, `emptyState()`, and (de)serialization helpers. No I/O, never throws on malformed input (garbage → treated as empty).
- `runFullscan` (in `src/orchestrate/fullscan.mjs`) extended with injected `loadState`/`saveState`, a `retry` policy (`{maxRetries, backoff}` with an injected `sleep`), and a `budget` (`{maxSteps, maxStepsPerStage}`) — all optional and defaulting to today's behavior (no resume file, no retry, no budget) so existing callers/tests are unchanged. The runner-invocation site classifies runner outcomes: `ok` / `denied` / `transient`; only `transient` is retried; every completed unit is `markDone`+`saveState`; a `--resume` load skips `isDone` units; the budget stops planning when exceeded.
- `bin/bh-fullscan.mjs` wires real `loadState`/`saveState` (a JSON file at `engagements/<active>/output/fullscan-state.json`), a real bounded `sleep`, and the new flags: `--resume`, `--max-retries N` (default 0 = off, conservative), `--max-steps N`, `--max-steps-per-stage N`. Fail-closed behavior unchanged.
- `pentest-workflow` skill + `/fullscan` command updated to document resume/retry/budget (still truthful about the unchanged `bh-exec` guarantees).
- **REAL e2e**: a real `bh-fullscan` run against a live nginx target that is (a) run once to partial/complete, then **`--resume`d** and shown to skip already-done units (no duplicate audit ALLOWs for done steps), and (b) shown to retry a transient (non-DENY) failure and still complete. Controller-run, real Docker.
- All existing tests green; README updated in this phase's PR.

---

## 2. Core: run-state model (`src/orchestrate/run-state.mjs`, pure)

A tiny, deterministic, never-throws module. State is a plain object `{ version, done: { [key]: true } }`.
- `stepKey({stage, tool, target}) -> string` — a stable key from the identifying tuple (e.g. `"<stage>|<tool>|<target>"`). Deterministic; no time/random.
- `emptyState() -> {version, done:{}}`.
- `isDone(state, key) -> boolean` — false for a missing/garbage state.
- `markDone(state, key) -> state` — returns a new state with `key` recorded (pure; caller persists).
- `parseState(text) -> state` / `serializeState(state) -> text` — tolerant: malformed JSON or wrong shape → `emptyState()` (never throws).

A stage is considered done when all its planned steps are done (recomputed each run from `targetsForStage` — the plan is deterministic, so re-deriving it and skipping done steps is safe and self-correcting if the maps changed).

## 3. Driver changes (`src/orchestrate/fullscan.mjs`, injectable)

`runFullscan({ runner, synth, loadMaps, scope, log, loadState, saveState, sleep }, { exploit, resume, retry, budget }) -> summary` — all new fields optional:
- **Resume:** if `resume`, `state = loadState()` once at start (else `emptyState()`). Before running a step, compute `key = stepKey(step)`; if `isDone(state, key)`, skip it (log `resume: skip <key>`), do not call `runner`. After a step completes with `ok` (or a terminal `denied` — a DENY is a *settled* outcome, so mark it done too so resume doesn't re-attempt a known-denied step), `state = markDone(state, key)` and `saveState(state)`.
- **Retry:** wrap the `runner` call. The runner returns/throws an outcome the driver classifies as `ok` | `denied` | `transient`. `denied` → skip, mark done, never retry. `transient` → retry up to `retry.maxRetries` with `await sleep(retry.backoff(attempt))` between attempts; if still failing, log and skip (non-fatal, same as today). `ok` → done. `maxRetries` defaults to 0 (behavior identical to today).
- **Budget:** track `stepsRun` (per run) and `stepsThisStage`. Before running a step, if `budget.maxSteps` reached → stop planning entirely (log `budget: maxSteps reached`), finish with findings+report over what exists. `budget.maxStepsPerStage` → stop the current stage early, continue to the next. Budgets never increase work.
- Determinism preserved: same inputs + same injected outcomes → same sequence, same saved state. `saveState`/`sleep`/`loadState` are injected (mock in tests; no real fs/timer in unit tests).
- `summary` gains: `resumedSkipped` count, `retried` count, `budgetStopped` flag/reason.

**The runner contract** (`runner({tool,target,flags,stage}) -> outcome`) is extended so the driver can classify: the injected/real runner returns a small result object `{status: "ok"|"denied"|"transient"}` (the real CLI runner maps exit 0 → ok, exit 2 → denied, other non-zero/spawn error → transient). Existing tests that pass a runner returning `undefined`/throwing keep working: `undefined` → `ok`, a throw → `transient` (matches today's skip-not-fatal), so the default (maxRetries 0) reproduces current behavior exactly.

## 4. CLI (`bin/bh-fullscan.mjs`)
New flags (all optional, conservative defaults = today's behavior):
- `--resume` — load/save `engagements/<active>/output/fullscan-state.json`; skip done units.
- `--max-retries N` (default 0) — retry transient (non-DENY) failures up to N with a bounded backoff (a fixed schedule, e.g. `min(baseMs * 2^attempt, capMs)`; the real `sleep` is `setTimeout`-based; NO random jitter → deterministic).
- `--max-steps N`, `--max-steps-per-stage N` (default unset = unbounded) — hard ceilings.
The real runner now returns `{status}` (exit 0 ok / exit 2 denied / else transient) instead of void; the DENY path stays logged-and-skipped. `saveState` writes the JSON atomically-enough (write file; it's small, single-writer, sequential). Everything else (fail-closed code 3, per-host output files, synth chain) unchanged.

## 5. Skill + command
`pentest-workflow` SKILL.md + `/fullscan` gain a short section: long scans can be `--resume`d after an interruption; transient tool failures can be retried with `--max-retries`; a run can be capped with `--max-steps`. Reiterate: retry re-runs the **identical bounded** `bh-exec` command and a scope/safety DENY is never retried; budgets only reduce work. No external refs; English only.

## 6. Safety analysis
| Concern | Bound |
|---|---|
| Retry a failed step | only NON-DENY transient failures; the retried command is byte-identical (same bounded flags, same `bh-exec`); a scope/safety DENY is final and never retried |
| Resume | reads/writes one JSON file under the engagement's own `output/`; no new network/tool surface; a done-marked DENY stays skipped on resume |
| Budget | strictly reduces autonomous action (a hard ceiling); can never widen scope or add steps |
| No bypass | unchanged — every step still `bh-exec <tool> --target … -- <bounded flags>`; the guard hook still denies direct tool calls |
| Determinism/audit | sequential order preserved; state/sleep injected; no time/random in the pure model |

The phase adds resilience and a ceiling; it removes no guardrail and adds no capability a manual `bh-exec` sequence couldn't already do.

## 7. Acceptance criteria
| # | Test | Expect |
|---|---|---|
| S1 | run-state model: `stepKey` stable/deterministic; `isDone`/`markDone` correct; `parseState` on garbage → empty (no throw); round-trip serialize→parse | correct pure model |
| S2 | `runFullscan` resume: with a pre-seeded state marking some steps done + a mock runner, done steps are skipped (runner not called for them), remaining run; `saveState` called per completed unit; summary `resumedSkipped` correct | correct resume |
| S3 | `runFullscan` retry: a runner returning `transient` for the first K attempts then `ok` → retried K times (injected `sleep` counted), step ultimately ok; a `denied` outcome is NEVER retried and is marked done; `maxRetries:0` reproduces today's behavior exactly | correct bounded retry |
| S4 | `runFullscan` budget: `maxSteps`/`maxStepsPerStage` stop work at the ceiling (later steps/stages skipped), findings+report still run, summary `budgetStopped` set | correct ceiling |
| S5 | `bh-fullscan` CLI: `--resume`/`--max-retries`/`--max-steps` parsed + wired (stubbed spawn asserts the state file path + that a re-run skips done steps); fail-closed unchanged | correct wiring |
| S6 | full `bun test` green | 534+ pass |
| E2E | **REAL:** live nginx + `bh:base`. Run `bh-fullscan --no-exploit`, capture state; run again with `--resume` → assert done stages are skipped (audit shows no duplicate ALLOWs for already-done steps) and a real `report.md` still results; separately, force a transient (non-DENY) failure on one step and assert `--max-retries` retries then the scan completes. Controller-run. | real resilient scan |

---

## 8. Deferred / notes
- **Parallel tool execution** (bounded concurrency) → a later phase; it trades away the clean sequential audit ordering and needs its own safety design.
- **New attack domains** (network/AD, mobile, CTF) + **Burp MCP** → Phase 8; these add new attack surface and each needs its own catalog/Docker/safety work + security review.
- **Intelligence/prioritization layer** (cross-finding correlation, risk scoring) → future; additive analysis over existing data.
- Tracked pre-existing follow-ups remain: `fase-*` → `phase-*` filename cleanup; `now`-non-function throw in map modules; safety non-finite numeric cap; sqlmap output regex version-drift; a CI `bun test` workflow.
