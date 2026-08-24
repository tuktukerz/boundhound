# Phase 4 — Verification: Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Consolidate the three per-tool maps into one normalized, severity-scored, de-duplicated, actively-re-verifiable `findings.json`, via a pure findings module + a `bh-findings` CLI + a self-authored `pentest-verify` skill, proven by a REAL e2e — reusing already-installed/bounded tools (no new tool, catalog, Docker, or safety change).

**Spec:** `docs/specs/2026-08-25-fase-4-verify-design.md`

## Global Constraints
- NO new attack tool; NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, `bin/bh-exec.mjs`. (Any such edit is a flagged deviation.)
- Re-verification re-runs the SAME bounded check that produced a finding (same flags), via `bh-exec` only; never escalates intrusiveness.
- Pure functions do NO I/O; parsers/synth NEVER throw on bad input. Deterministic `id` (no time/random in the id).
- Node ESM `.mjs`, `bun test`, no build step. English only. Deny-by-default/fail-closed/audit unchanged.

---

### Task 1: `findings` module — buildFindings + applyVerification (pure)

**Files:** Create `src/verify/findings.mjs`, `src/verify/findings.test.mjs`, fixtures under `test/fixtures/verify/` (a `recon-map.json`, `enum-map.json`, `exploit-map.json`).

**Interfaces produced (spec §2):**
- `buildFindings({reconMap, enumMap, exploitMap}, {now} = {}) -> { generated_at, findings: [<normalized>] }` — map each source per spec §2.2; severity table-driven; DEDUP by a deterministic `id` (stable hash of `category|type|target|key`, NO time/random); sqli `vulnerable:true` → severity high, `verified:true`, `confidence:confirmed`; `vulnerable:false` → skip. Missing/empty maps tolerated.
- `applyVerification(findings, recheckResults) -> findings` — `recheckResults`: `[{ id?, type?, target?, key?, reproduced: bool }]`; sets `verified:true`+`confidence:confirmed` on matched reproduced findings; `reproduced:false` leaves `verified:false` (NEVER drops the finding).
- A small `severityFor(type, sourceSeverity)` helper, unit-tested.

- [ ] Read `src/recon/recon-map.mjs`, `src/enum/enum-map.mjs`, `src/exploit/exploit-map.mjs` for the exact map shapes to consume.
- [ ] Write fixtures + failing tests: V1 (each source → correct normalized findings + severity), V2 (dedup collapses same-id, keeps highest severity; same input → identical id twice), V3 (applyVerification flip both directions; not-reproduced NOT dropped). Include a garbage/empty-maps test (no throw). Run → RED.
- [ ] Implement pure functions (no I/O, no throw). Deterministic id (e.g. a simple stable string hash of the key — reuse Node `crypto`? prefer a tiny pure hash so it's dependency-free and deterministic; document the choice).
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(verify): findings model — buildFindings + applyVerification`

---

### Task 2: `bin/bh-findings.mjs` CLI

**Files:** Create `bin/bh-findings.mjs`, `bin/bh-findings.test.mjs`.

**Consumes:** Task 1 module + the existing parsers (`parseNucleiJsonl`, `parseHttpxJsonl`, `parseNmapGrepable`, `parseSqlmapOutput`).

**Interfaces produced (spec §3):** CLI mirrors `bin/bh-enum-map.mjs` exactly. Reads (each optional) `output/{recon/recon-map.json, enum/enum-map.json, exploit/exploit-map.json}` + `output/verify/recheck/*` (re-verification tool outputs parsed via the existing parsers into recheckResults). Writes `output/verify/findings.json`. Missing inputs → empty; fail-closed on no active engagement (code 3).

- [ ] Read `bin/bh-enum-map.mjs` first to copy conventions.
- [ ] Write failing tests: temp engagement with the three maps (+ a recheck `*.jsonl` under `output/verify/recheck/`) → `findings.json` matches consolidated+verified shape; missing maps → empty findings no crash; no active engagement → code 3. Run → RED.
- [ ] Implement thin CLI (reads maps + recheck dir, calls buildFindings + applyVerification, writes findings.json). Interpret recheck outputs by REUSING the phase 1-3 parsers (a nuclei recheck reproduces a finding if the same template_id fires on the same host; httpx if a live status returns; nmap if the port is still open).
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(verify): bh-findings CLI — consolidate maps + rechecks into findings.json`

---

### Task 3: `pentest-verify` skill + `/verify` command

**Files:** Create `.claude/skills/pentest-verify/SKILL.md`, `.claude/commands/verify.md`. Create `test/verify-skill.test.mjs`.

**Interfaces produced (spec §4):** self-authored skill orchestrating the re-verification pass (re-run each unverified candidate's SAME bounded check via bh-exec into `output/verify/recheck/`, then `bh-findings`), + `/verify`.

- [ ] Read `.claude/skills/pentest-enum/SKILL.md` for style/conventions + the nuclei/httpx/nmap catalog entries for exact re-run flags.
- [ ] Write `test/verify-skill.test.mjs`: frontmatter (`name: pentest-verify`, description w/ `Triggers:`, `phase` includes `"verify"` — NOTE: `phase` in frontmatter is free text, "verify" is fine; check the loader tolerates it, else use an existing phase value and note it), tools lists the reuse tools; `/verify` command with `<command-instruction>`; POSITIVE routing assertions (re-run invocations go via `bh-exec.mjs <tool> --target`, using ONLY cataloged flags — no new/undeclared flags, no escalation to sqlmap-dump/etc.); NO external refs; NO residual Indonesian.
- [ ] Run → FAIL. Author the skill (our words): consumes prior maps, re-runs same bounded checks, never escalates, keeps non-reproducing findings flagged. Write `/verify`.
- [ ] Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(verify): pentest-verify skill + /verify command`

---

### Task 4: REAL e2e — re-verification vs a live target

**Files:** Create `test/verify-e2e.test.mjs`, fixtures as needed (`test/fixtures/verify/nginx-detect.yaml` — reuse/copy the enum phase's bundled nuclei template).

**Interfaces produced:** real, offline, deterministic e2e (spec §6 E2E). Mirror `test/enum-e2e.test.mjs` (skip guard, unique per-pid names prefix `bh-e2everify`, prefix-sweep, fail-safe afterAll, dotted-FQDN).

- [ ] Write `test/verify-e2e.test.mjs`: docker available (else skip): live nginx target + `bh:base` engagement container; engagement with target in-scope. Seed an `enum-map.json` (or run a quick real nuclei to produce one) with a nuclei finding for the target. Then:
  - Real re-verify: `node bin/bh-exec.mjs nuclei --target http://<target-fqdn> -- -t /tmp/nginx-detect.yaml -jsonl -disable-update-check` (template copied in via docker cp, as in enum e2e) → stdout to `output/verify/recheck/<host>.jsonl`.
  - `node bin/bh-findings.mjs --data-dir <tmp>` → assert `findings.json` has the nuclei finding with `verified:true`.
  - Assert an OUT-OF-SCOPE re-check target (`bh-exec nuclei --target http://10.99.99.99`) → exit 2 DENY + audit.
  - Fail-safe teardown.
- [ ] Controller RUNS it for real (`bun test test/verify-e2e.test.mjs`, docker up) + captures `findings.json`. If blocked, report specifics (don't fake).
- [ ] FULL `bun test`.
- [ ] Commit: `test(verify): real e2e — re-verification flips a finding to verified`

---

### Task 5: README + plugin.json

**Files:** Modify `README.md`, `.claude-plugin/plugin.json`.

- [ ] README: status/roadmap → Phase 4 done; add a **Verification** section (consolidates recon/enum/exploit maps → one severity-scored, de-duplicated `findings.json`; active re-verification re-runs each finding's SAME bounded check via bh-exec to set `verified`; `/verify`; non-reproducing findings kept+flagged; real e2e proves a verified flip). Update `bun test` count; Structure paths (`src/verify/`, `bin/bh-findings.mjs`, `.claude/skills/pentest-verify/`, `/verify`). plugin.json description → Phase 4. No external refs, no residual "Fase".
- [ ] FULL `bun test`.
- [ ] Commit: `docs(verify): README Phase 4 verification capability + plugin description`

---

## Self-Review
- Spec coverage: §2→T1, §3→T2, §4→T3, §6 e2e→T4, README→T5. ✅
- No new tool/catalog/Docker/safety change (asserted by their absence from diffs). Re-verification reuses bounded checks. Deterministic id, pure never-throw synth. Real e2e re-verifies against a live target.
