# Design Spec — Phase 4: Verification

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0–3 merged.
**Guiding principle:** turn the raw per-tool maps (recon/enum/exploit) into ONE normalized, severity-scored, de-duplicated `findings.json`, and **actively re-verify** each candidate finding (re-run its confirming check through `bh-exec`) so the report contains *verified* findings, not raw tool noise. No new attack tool — this phase reuses the tools already installed and reasons over their output.

---

## 1. Goal & Non-Goals

### Goal
Consolidate `recon-map.json` + `enum-map.json` + `exploit-map.json` into a single `findings.json`: each finding normalized (id, category, type, target, severity, confidence, evidence), **de-duplicated**, **severity-mapped**, and marked `verified` when a re-run of its confirming check reproduces it — all re-runs going through the `bh-exec` choke point (scope + safety + audit + container).

### Non-Goals (STRICT)
- ❌ No new attack tool, no new catalog entry, no Docker change, no safety-check change — Phase 4 reuses nmap/httpx/nuclei/ffuf/sqlmap already cataloged + safety-capped, and adds only synthesis + a skill + a CLI. (If a review shows a needed catalog/safety tweak, that's a flagged deviation, not planned.)
- ❌ No change to `command-builder.mjs` / `bh-exec.mjs`.
- ❌ Re-verification does NOT escalate intrusiveness — it re-runs the SAME bounded check that produced the finding (same flags), never a heavier one.

### Definition of Done
- `src/verify/findings.mjs` (pure): `buildFindings({reconMap, enumMap, exploitMap}, {now})` → normalized+deduped+severity-scored findings; `applyVerification(findings, recheckResults)` → flips `verified`.
- `bin/bh-findings.mjs` (CLI, mirrors bh-*-map): reads the three maps + any `output/verify/*` re-check outputs → writes `engagements/<name>/output/verify/findings.json`.
- `pentest-verify` skill + `/verify` command orchestrate the re-verification pass (re-run each candidate via bh-exec) then rebuild findings.
- **REAL e2e**: build findings from real maps AND perform a real re-verification against a live target (e.g. re-fire a nuclei template / re-probe httpx against a local nginx) so a finding flips to `verified:true`; then `bh-findings` produces the consolidated `findings.json`. Controller-run.
- All existing tests green; README updated in this phase's PR.

---

## 2. Core: the findings model

### 2.1 Normalized finding
```jsonc
{
  "id": "<stable hash of category|type|target|key>",
  "category": "recon" | "enum" | "exploit",
  "type": "open-port" | "http-service" | "subdomain" | "content" | "nuclei" | "sqli",
  "target": "<host or url>",
  "severity": "info" | "low" | "medium" | "high" | "critical",
  "confidence": "confirmed" | "reported",
  "evidence": { ...source-specific facts... },
  "verified": false
}
```

### 2.2 Mapping the three maps → findings (`buildFindings`, pure)
- **recon-map**: each `hosts[].ports[]` open port → `{category:recon, type:open-port, target:host, severity:info, evidence:{port,proto,service}}`; each `http_services[]` → `{type:http-service, target:url, severity:info, evidence:{status_code,title,tech}}`; each `subdomains[]` → `{type:subdomain, target:name, severity:info}`.
- **enum-map**: each `findings[]` (nuclei) → `{category:enum, type:nuclei, target:host, severity:<nuclei severity>, evidence:{template_id,name,matched_at}}`; each `content[]` (ffuf path) → `{type:content, target:url, severity:info, evidence:{path,status,length}}`.
- **exploit-map**: each `findings[]` with `vulnerable:true` → `{category:exploit, type:sqli, target, severity:high, confidence:confirmed, verified:true, evidence:{dbms,injection_points}}`. (sqlmap already confirmed it → `verified:true` immediately.) `vulnerable:false` → no finding.
- **Severity mapping** is table-driven and unit-tested. **Dedup**: findings with the same `id` collapse to one (keep the highest severity + merge evidence). `id` = a stable, deterministic hash (no randomness/time in the id).
- `confidence`: `confirmed` for exploit/sqli and any re-verified finding; `reported` otherwise.

### 2.3 Re-verification (`applyVerification`, pure)
`applyVerification(findings, recheckResults)` takes the findings + a list of re-check outcomes `[{ id | (type,target,key), reproduced: bool }]` and sets `verified:true` (and `confidence:"confirmed"`) on findings whose confirming re-run reproduced. Re-check outcomes are produced by the skill re-running the tool and are interpreted by REUSING the existing parsers (`parseNucleiJsonl`, `parseHttpxJsonl`, `parseNmapGrepable`, `parseSqlmapOutput`) — a nuclei finding is `reproduced` if the same `template_id` fires again on the same host; an http-service if httpx still returns a live status; an open-port if nmap still shows it open. Deterministic, no I/O.

---

## 3. `bin/bh-findings.mjs` (CLI)
Mirrors `bin/bh-enum-map.mjs`/`bh-recon-map.mjs` exactly (`--data-dir`, `process.argv[1]` main-detection, `dataRoot()`, fail-closed on no active engagement). Reads (each optional, missing → empty):
- `engagements/<active>/output/recon/recon-map.json`
- `engagements/<active>/output/enum/enum-map.json`
- `engagements/<active>/output/exploit/exploit-map.json`
- `engagements/<active>/output/verify/recheck/*` (re-verification tool outputs: `*.jsonl` nuclei, `*.gnmap` nmap, `*.httpx.jsonl` httpx) — parsed via the existing parsers into recheck results.
Writes `engagements/<active>/output/verify/findings.json`. Not a network tool.

---

## 4. `pentest-verify` skill + `/verify` command
Self-authored (our words, no external refs). `.claude/skills/pentest-verify/SKILL.md` orchestrates, ALL re-runs via `bh-exec`:
1. Require an active engagement + scope + at least one prior map (recon/enum/exploit). If none, tell the operator to run the earlier phases.
2. Build the candidate findings (run `bh-findings` once to see them, or reason from the maps).
3. For each UNVERIFIED candidate that is re-checkable, re-run its SAME bounded check via `bh-exec` into `output/verify/recheck/` — e.g. nuclei finding → `bh-exec nuclei --target http://<host> -- -jsonl -disable-update-check -t <template-or-severity>`; http-service → `bh-exec httpx --target <url> -- -silent -json`; open-port → `bh-exec nmap --target <host> -- -sT -Pn -p <port> -oG -`. NEVER escalate to a heavier/destructive check. sqlmap SQLi findings are already confirmed — do not re-run sqlmap unless asked.
4. Re-run `bh-findings` → `findings.json` with `verified` flags set.
Document: scope re-checked by bh-exec; re-verification stays within the same safety envelope; a finding that no longer reproduces is kept but flagged `verified:false` (do not silently drop it).
`.claude/commands/verify.md` (`/verify`) mirrors `/enum`.

---

## 5. Safety analysis
| Capability | Bound |
|---|---|
| Re-running checks | only the SAME bounded flags that produced the finding, via bh-exec (scope + safety + audit + container); no escalation |
| No new tool/flags | reuses cataloged tools; nothing new to bound |
| findings.json | derived data only; `bh-findings` is not a network tool |

No new attack surface; Phase 4 is a reasoning/consolidation layer over already-bounded capabilities.

---

## 6. Acceptance criteria

| # | Test | Expect |
|---|---|---|
| V1 | `buildFindings` maps recon/enum/exploit fixtures → correct normalized findings with correct severity per type; sqli `vulnerable:true` → severity high + verified:true; `vulnerable:false` → no finding | correct mapping |
| V2 | dedup: two inputs producing the same `id` collapse to one (highest severity kept); `id` deterministic (same input → same id, no time/random) | dedup + stable id |
| V3 | `applyVerification`: a recheck result `{reproduced:true}` flips the matching finding to `verified:true`+`confidence:confirmed`; `{reproduced:false}` leaves `verified:false` (finding NOT dropped) | verify flip |
| V4 | `bh-findings` CLI: temp engagement with the three maps + a recheck output → writes `findings.json` matching the consolidated shape; missing maps → empty findings, no crash | correct CLI |
| V5 | `pentest-verify` skill: frontmatter valid; `/verify` command; re-run invocations use only cataloged flags + go via bh-exec; NO external refs; no residual Indonesian | valid skill |
| V6 | full `bun test` green | 366+ pass |
| E2E | **REAL:** live nginx target; a nuclei-detect finding built into candidate findings; real `bh-exec nuclei` re-fire reproduces it → `bh-findings` marks it `verified:true` in `findings.json`; assert an out-of-scope re-check target DENYs. Offline/deterministic, controller-run. | real re-verification |

---

## 7. Deferred / notes
- Confidence scoring beyond confirmed/reported (numeric, CVSS) — later.
- False-positive heuristics beyond "did it reproduce" — later.
- The tracked safety-check `Number.isFinite` hardening and `fase-*` filename English follow-ups remain deferred.
