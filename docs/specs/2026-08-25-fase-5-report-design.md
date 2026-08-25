# Design Spec — Phase 5: Reporting

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0–4 merged.
**Guiding principle:** render the verified `findings.json` (+ the engagement's own metadata) into a professional, human-readable **pentest report** (markdown) — the actual deliverable an operator hands to a client. Offline document generation; no tools, no attack surface.

---

## 1. Goal & Non-Goals

### Goal
`findings.json` (Phase 4) + the engagement's `scope.yaml` (name, authorization, scope, mode) + an audit summary → a well-structured `report.md`: title/metadata, executive summary (counts by severity + verified), scope, methodology, findings grouped by severity (each with target, severity, confidence, verified status, evidence, and **remediation guidance**), and an appendix. Produced by a pure renderer + a `bh-report` CLI + a `pentest-report` skill.

### Non-Goals (STRICT)
- ❌ No new attack tool, no catalog/Docker/safety-check/command-builder/bh-exec change (offline doc-gen). Reuses `parseScope`/the findings model only.
- ❌ No fabricated content — the report renders ONLY what's in `findings.json` + `scope.yaml`; it never invents findings, severities, or evidence.
- ❌ Not HTML/PDF in v1 — markdown only (HTML/PDF is a later expansion). Markdown is portable and reviewable.

### Definition of Done
- `src/report/report.mjs` (pure): `buildReport({findings, meta, auditSummary}, {now}) -> string` (markdown).
- `bin/bh-report.mjs` (CLI, mirrors bh-findings): reads `output/verify/findings.json` + the active engagement's `scope.yaml` (via `parseScope`) + optionally summarizes `audit.log` → writes `output/report/report.md`.
- `pentest-report` skill + `/report` command.
- **REAL e2e**: a real `bh-findings` run (over realistic maps in a temp engagement) → real `findings.json`, then a real `bh-report` subprocess → `report.md`; assert the report contains the exec-summary severity counts, a section per present severity, each finding's target + remediation, and the engagement metadata. Offline/deterministic, controller-run. (Reporting is inherently offline — the real e2e is a real multi-CLI subprocess chain over real engagement data; no container needed.)
- All existing tests green; README updated in this phase's PR.

---

## 2. Core: the report renderer (`src/report/report.mjs`, pure)

`buildReport({ findings, meta, auditSummary }, { now } = {}) -> string` — deterministic markdown, no I/O, never throws:
- **`findings`**: the `findings.json` `findings` array (Phase 4 shape). Missing/garbage → treated as empty (report still renders with "no findings").
- **`meta`**: `{ engagement, authorization, mode, scope_enforcement, in_scope, out_of_scope, notes }` (from `parseScope`). Missing fields → sensible placeholders (e.g. "(unspecified)"); NEVER throw.
- **`auditSummary`** (optional): `{ allow, deny, total }` counts, rendered in the appendix. Missing → omit that appendix line.

**Report structure (markdown):**
1. **Title + metadata** — `# Penetration Test Report — <engagement>`, generated date (from injected `now`), authorization on record, mode, scope_enforcement.
2. **Executive summary** — a severity table (critical/high/medium/low/info counts) + how many are `verified`. One or two plain-English sentences derived from the counts (e.g. "N findings, of which M are confirmed high-or-critical").
3. **Scope** — in_scope domains/cidrs, out_of_scope, from meta.
4. **Methodology** — the phase chain (recon → enum → exploit → verify) and that every tool ran through the enforced `bh-exec` choke point (scope + safety + audit + container). Static, truthful text.
5. **Findings** — grouped by severity, **critical → high → medium → low → info** (skip empty groups). Each finding: a heading (`### [<SEVERITY>] <type> — <target>`), a line for confidence + verified status, an **Evidence** block (rendered from the finding's `evidence`), and a **Remediation** block from a per-`type` remediation table (§2.1). Within a severity group, order deterministically (e.g. by target then id).
6. **Appendix** — audit summary (ALLOW/DENY counts) if provided; a note that raw tool output lives under `output/`.

### 2.1 Remediation table (per finding `type`)
A static, table-driven map, unit-tested. Examples:
- `sqli` → "Use parameterized queries / prepared statements; validate & escape input; apply least-privilege DB accounts."
- `nuclei` → "Review the flagged template's category; patch/upgrade the affected component or apply the documented mitigation."
- `open-port` → "Confirm the service is intended to be exposed; restrict with a firewall/security-group; disable if unnecessary."
- `http-service` / `content` / `subdomain` → informational guidance (attack-surface awareness; remove stale/exposed content; decommission unused subdomains).
- unknown type → a generic "investigate and remediate per your organization's process."

**Determinism:** same `findings`+`meta`+`now` → byte-identical markdown (no time/random except the injected `now`). Severity/type ordering fixed.

---

## 3. `bin/bh-report.mjs` (CLI)
Mirrors `bin/bh-findings.mjs` exactly (`--data-dir`, `process.argv[1]` main-detection, `dataRoot()`, fail-closed on no active engagement code 3). Reads:
- `engagements/<active>/output/verify/findings.json` (missing → empty findings — still renders a valid "no findings yet" report).
- `engagements/<active>/scope.yaml` via `parseScope` for `meta` (fail-closed if scope is broken, same as the rest of the system — a report for a broken engagement is refused, consistent with deny-by-default).
- `engagements/<active>/audit.log` → summarize ALLOW/DENY counts (best-effort; missing → omit).
Writes `engagements/<active>/output/report/report.md`. Not a network tool.

---

## 4. `pentest-report` skill + `/report` command
Self-authored (our words, no external refs). `.claude/skills/pentest-report/SKILL.md`:
1. Require an active engagement + `findings.json` (tell the operator to run `/verify` first if missing).
2. Run `bh-report` (via the plugin/dev-mode invocation) → `output/report/report.md`.
3. Summarize the report for the operator (top findings by severity); note that the report renders ONLY verified engagement data and never invents findings.
`.claude/commands/report.md` (`/report`) mirrors `/verify`. `tools: []` (no external tool — it's a doc generator). `phase: ["report"]`.

---

## 5. Safety analysis
| Capability | Bound |
|---|---|
| Report generation | pure rendering of `findings.json` + `scope.yaml`; `bh-report` is not a network tool; fail-closed on a broken scope (consistent with the rest) |
| No fabrication | renders only present data; unknown types get generic remediation, never invented severity/evidence |
No new attack surface.

---

## 6. Acceptance criteria
| # | Test | Expect |
|---|---|---|
| R1 | `buildReport` with a findings fixture (mixed severities incl. a verified sqli + unverified nuclei) → markdown containing: the title+engagement, a severity-count table, a section per present severity in crit→info order, each finding's target + remediation, methodology + scope | correct structure |
| R2 | determinism: same input+`now` → byte-identical output; empty findings → a valid "no findings" report (no throw); missing meta fields → placeholders (no throw) | deterministic + robust |
| R3 | remediation table: each known type maps to its guidance; unknown type → generic guidance | correct remediation |
| R4 | `bh-report` CLI: temp engagement with a `findings.json` + `scope.yaml` → writes `report.md` with the expected content; broken scope → fail-closed code 3; missing findings → valid empty report | correct CLI |
| R5 | `pentest-report` skill: frontmatter valid; `/report` command; no external refs; no residual Indonesian | valid skill |
| R6 | full `bun test` green | 425+ pass |
| E2E | **REAL:** real `bh-findings` (over realistic maps in a temp engagement) → real `findings.json`; then real `bh-report` subprocess → `report.md`; assert exec-summary counts, a section per present severity, each finding's target + remediation, and the engagement metadata all appear. Offline/deterministic, controller-run. | real report from real data |

---

## 7. Deferred / notes
- HTML/PDF rendering, templating themes, CVSS scoring, client branding → Phase 7 expansion.
- The tracked `now`-non-function + `fase-*` filename follow-ups remain deferred.
