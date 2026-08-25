# Phase 5 — Reporting: Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Render `findings.json` + the engagement's `scope.yaml` into a professional pentest `report.md`, via a pure renderer + a `bh-report` CLI + a self-authored `pentest-report` skill, proven by a REAL e2e — offline doc-gen, no new tool/catalog/Docker/safety change.

**Spec:** `docs/specs/2026-08-25-fase-5-report-design.md`

## Global Constraints
- NO new attack tool; NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, `bin/bh-exec.mjs`. Reuse `src/scope/scope-parser.mjs` (`parseScope`) + the findings shape only.
- Renderer is PURE (no I/O), NEVER throws, DETERMINISTIC (same input+`now` → byte-identical). No fabricated content — render only present data.
- Node ESM `.mjs`, `bun test`, no build step. English only. Deny-by-default/fail-closed unchanged (`bh-report` fail-closes on a broken scope).

---

### Task 1: report renderer (`src/report/report.mjs`, pure)

**Files:** Create `src/report/report.mjs`, `src/report/report.test.mjs`, fixtures under `test/fixtures/report/` (a realistic `findings.json` with mixed severities incl. a verified sqli + an unverified nuclei + an open-port + info items, and a parsed-scope `meta` object).

**Interfaces produced (spec §2):** `buildReport({findings, meta, auditSummary}, {now} = {}) -> string`; a `remediationFor(type) -> string` helper (table-driven, spec §2.1); a severity/type ordering. Sections per spec §2: title+metadata, executive summary (severity counts + verified count), scope, methodology, findings grouped crit→high→med→low→info (skip empty groups; each: heading, confidence+verified, evidence, remediation), appendix (audit summary if present).

- [ ] Read `src/verify/findings.mjs` (finding shape) + `src/scope/scope-parser.mjs` (`parseScope` output = the `meta` shape) first.
- [ ] Write fixtures + failing tests: R1 (structure — title/engagement, severity table, a section per present severity in crit→info order, each finding target+remediation, methodology, scope), R2 (determinism: same input+now → identical string; empty findings → valid "no findings" report, no throw; missing meta fields → placeholders, no throw), R3 (remediationFor: each known type → its guidance; unknown → generic). Run → RED.
- [ ] Implement pure renderer (no I/O, no throw, deterministic). Fixed severity order + within-group deterministic order (by target then id).
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(report): report renderer — buildReport + remediation table`

---

### Task 2: `bin/bh-report.mjs` CLI

**Files:** Create `bin/bh-report.mjs`, `bin/bh-report.test.mjs`.

**Consumes:** Task 1 renderer + `parseScope`.

**Interfaces produced (spec §3):** CLI mirrors `bin/bh-findings.mjs`. Reads `output/verify/findings.json` (missing → empty findings), the engagement `scope.yaml` via `parseScope` (broken scope → fail-closed code 3, consistent with the system), and summarizes `audit.log` (best-effort ALLOW/DENY counts; missing → omit). Writes `output/report/report.md`. `--data-dir` idiom, `process.argv[1]` main-detection, fail-closed on no active engagement.

- [ ] Read `bin/bh-findings.mjs` first for conventions.
- [ ] Write failing tests: temp engagement (mkdtemp) with `.active`=acme + a valid `scope.yaml` + a `output/verify/findings.json` → run CLI → assert `output/report/report.md` written with the expected content (title, a finding's target, remediation); broken/missing scope.yaml → code 3 fail-closed (no report written); missing findings.json → still writes a valid "no findings" report (parseScope OK). Assert an `audit.log` with a couple ALLOW/DENY lines is summarized in the report. Run → RED.
- [ ] Implement thin CLI. Focused tests → GREEN. Full `bun test` before committing.
- [ ] Commit: `feat(report): bh-report CLI — findings.json + scope → report.md`

---

### Task 3: `pentest-report` skill + `/report` command

**Files:** Create `.claude/skills/pentest-report/SKILL.md`, `.claude/commands/report.md`. Create `test/report-skill.test.mjs`.

**Interfaces produced (spec §4):** self-authored skill: require active engagement + `findings.json` (else run `/verify` first), run `bh-report`, summarize; `/report` command. `tools: []`, `phase: ["report"]`.

- [ ] Read `.claude/skills/pentest-verify/SKILL.md` for style/conventions.
- [ ] Write `test/report-skill.test.mjs`: frontmatter (`name: pentest-report`, description w/ `Triggers:`, `phase` includes `"report"`, `tools: []`); `/report` command with `<command-instruction>`; asserts the skill invokes `bh-report.mjs` (via the plugin/dev-mode form) and tells the operator the report renders ONLY verified engagement data (no fabrication); NO external refs; NO residual Indonesian.
- [ ] Run → FAIL. Author the skill + command (our words). Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(report): pentest-report skill + /report command`

---

### Task 4: REAL e2e — real report from real findings

**Files:** Create `test/report-e2e.test.mjs`, fixtures as needed under `test/fixtures/report/`.

**Interfaces produced:** a real, offline, deterministic multi-CLI e2e (spec §6 E2E).

- [ ] Write `test/report-e2e.test.mjs`: create a temp engagement (temp `--data-dir`, `.active`=acme, a real `scope.yaml`) seeded with realistic real-shaped maps under `output/{recon,enum,exploit}/` (reuse the Phase-1/2/3 fixture shapes) + optionally a recheck. Run REAL `node bin/bh-findings.mjs --data-dir <tmp>` → real `findings.json`; then REAL `node bin/bh-report.mjs --data-dir <tmp>` → `output/report/report.md`. Assert the report contains: the engagement name + authorization, the exec-summary severity counts consistent with the findings, a section per present severity, each finding's target, and a remediation line per finding type present. (This is a real subprocess chain over real engagement data; reporting is offline so no container is needed.)
- [ ] Controller RUNS it for real (`bun test test/report-e2e.test.mjs`) + captures the produced `report.md`. If blocked, report specifics.
- [ ] FULL `bun test`.
- [ ] Commit: `test(report): real e2e — bh-findings + bh-report produce a real report.md`

---

### Task 5: README + plugin.json

**Files:** Modify `README.md`, `.claude-plugin/plugin.json`.

- [ ] README: status/roadmap → Phase 5 done; add a **Reporting** section (renders `findings.json` + `scope.yaml` → a professional `report.md`: exec summary, scope, methodology, findings-by-severity with per-type remediation, appendix; `/report`; renders ONLY verified engagement data, never fabricates; real e2e proves a real report). Update `bun test` count; Structure paths (`src/report/`, `bin/bh-report.mjs`, `.claude/skills/pentest-report/`, `/report`). plugin.json description → Phase 5. No external refs, no residual "Fase".
- [ ] FULL `bun test`.
- [ ] Commit: `docs(report): README Phase 5 reporting capability + plugin description`

---

## Self-Review
- Spec coverage: §2→T1, §3→T2, §4→T3, §6 e2e→T4, README→T5. ✅
- No new tool/catalog/Docker/safety change. Renderer pure/deterministic/never-throws/no-fabrication. Fail-closed on broken scope. Real multi-CLI e2e over real data.
