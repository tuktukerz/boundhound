# Phase 8 — Burp MCP Safety Layer: Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** A second scope choke point so Burp Suite MCP tool calls (which bypass `bh-exec`) are scope-checked deny-by-default before they run — a pure guard module, wired into the existing PreToolUse hook, plus a scope-mirroring CLI and a `pentest-burp` skill — proven by a REAL e2e that drives the actual hook subprocess. Safety-first prerequisite for any Burp use; NO live Burp needed; NO new container attack surface.

**Spec:** `docs/specs/2026-08-25-phase-8-burp-mcp-safety-design.md`

## Global Constraints
- NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, `bin/bh-exec.mjs` (Burp is host-side, not a container tool).
- The guard is DENY-BY-DEFAULT and FAIL-CLOSED: no active scope / unresolvable target / out-of-scope ⇒ DENY. Never fail open. A false-deny is acceptable; a false-allow is a Critical defect.
- Preserve the existing hook decisions (Bash/WebFetch/WebSearch/Write/Edit) byte-for-byte; only ADD the Burp branch. Reuse `matchTarget` (`src/scope/scope-matcher.mjs`) verbatim for the scope decision.
- Pure guard module (no I/O, never throws). Node ESM `.mjs`, `bun test`, no build step. English only (also fix the stray "Fase 0" → "Phase 0" in `hooks/scope-guard.mjs`). No `Date.now()`/`Math.random()` in pure code.

---

### Task 1: Burp guard module — `src/guard/burp-guard.mjs` (pure)

**Files:** Create `src/guard/burp-guard.mjs`, `src/guard/burp-guard.test.mjs`.

**Interfaces produced (spec §2):** `isBurpMcpTool(toolName) -> bool` (`^mcp__` + case-insensitive `burp`); `extractBurpTarget(toolInput) -> string|null` (checks `url`,`target`,`targetUrl`,`host`(+`port`), then a raw request field's request-line URL / `Host:` header; null if none); `decideBurpMcp(toolInput, scopeConfig) -> {decision,reason}` (no scopeConfig → DENY "no-active-scope"; null target → DENY "burp-target-unresolved"; else `matchTarget(target, scopeConfig)`). Never throws.

- [ ] Read `src/scope/scope-matcher.mjs` (`matchTarget`/`normalizeTarget`) first.
- [ ] Write failing tests (B1/B2/B3): isBurpMcpTool matches `mcp__burp__*`/`mcp__pro_burp__*`, rejects `Bash`/`mcp__github__x`/`""`/non-string; extractBurpTarget from `{url}`/`{target}`/`{host}`/raw-request-with-Host; null when absent; decideBurpMcp deny-by-default (no scope → DENY, null target → DENY, out-of-scope → DENY, in-scope → ALLOW). Run → RED.
- [ ] Implement (pure, never-throws). Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(burp): pure Burp MCP scope guard (deny-by-default, fail-closed)`

---

### Task 2: hook wiring — `hooks/scope-guard.mjs` + `hooks/hooks.json`

**Files:** Modify `hooks/scope-guard.mjs`, `hooks/hooks.json`; extend `hooks/scope-guard.test.mjs`.

**Consumes:** Task 1.

**Interfaces produced (spec §3):** `decideFromEvent` routes a Burp MCP tool call through `decideBurpMcp` against the active engagement's parsed scope (loaded fail-closed — any error → deny); a Burp DENY is audited (extend `detail` to include the Burp target); existing branches unchanged. `hooks.json` matcher also catches Burp MCP tool names. Fix "Fase 0" → "Phase 0".

- [ ] Read current `hooks/scope-guard.mjs` + `hooks/hooks.json` + how bins load the active parsed scope (`src/scope/active-engagement.mjs`, `scope-parser.mjs`) first.
- [ ] Write failing tests (B4): `decideFromEvent` for a Burp MCP event → allow when in-scope, deny when out-of-scope / no active engagement / unresolvable; assert every EXISTING decision (Bash allow/deny, Write-Edit scope.yaml deny, WebFetch deny) is unchanged; the WebFetch reason now says "Phase 0" not "Fase 0". (Scope loading in the hook may need a temp-data-dir fixture like other hook tests — mirror them.) Run → RED.
- [ ] Implement the branch + matcher + wording fix (fail-closed scope load). Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(burp): route Burp MCP tool calls through the scope guard (deny-by-default)`

---

### Task 3: scope-mirror CLI — `bin/bh-burp-scope.mjs`

**Files:** Create `bin/bh-burp-scope.mjs`, `bin/bh-burp-scope.test.mjs`.

**Interfaces produced (spec §4):** CLI mirrors `bin/bh-report.mjs` conventions (`--data-dir`, `process.argv[1]`, `dataRoot()`, fail-closed code 3 on no active engagement / broken scope via `parseScope`/`loadActiveConfig`). Reads the active `scope.yaml` and emits a Burp Suite Target Scope JSON (include = `in_scope`, exclude = `out_of_scope`) to stdout AND writes `engagements/<active>/output/burp/target-scope.json`. Deterministic; not a network tool.

- [ ] Read `bin/bh-report.mjs` (fail-closed + conventions) + `src/scope/scope-parser.mjs` (the parsed shape) first.
- [ ] Write failing tests (B5): temp engagement with a real scope.yaml → CLI writes/prints a Burp Target Scope with the expected include/exclude entries derived from in_scope/out_of_scope; broken/absent scope → fail-closed code 3, nothing written. Run → RED.
- [ ] Implement. Focused tests → GREEN. Full `bun test` before committing.
- [ ] Commit: `feat(burp): bh-burp-scope — mirror scope.yaml into a Burp Target Scope`

---

### Task 4: `pentest-burp` skill + `/burp` command

**Files:** Create `.claude/skills/pentest-burp/SKILL.md`, `.claude/commands/burp.md`. Create `test/burp-skill.test.mjs`.

**Interfaces produced (spec §5):** self-authored skill; documents the separate-choke-point model, the host/Pro requirement, deny-by-default enforcement, and the `bh-burp-scope` mirror step; `/burp`.

- [ ] Read `.claude/skills/pentest-workflow/SKILL.md` for style. Read `bin/bh-burp-scope.mjs` for the invocation.
- [ ] Write `test/burp-skill.test.mjs`: frontmatter (`name: pentest-burp`, description w/ `Triggers:`, `phase` includes `"burp"`); `/burp` command with `<command-instruction>`; asserts the skill states Burp runs on the host / Burp Pro for active scan, that Burp MCP calls do NOT go through `bh-exec` but ARE scope-checked deny-by-default by the PreToolUse guard, that an out-of-scope Burp target is denied+audited, and that the operator must mirror scope via `bh-burp-scope`; requires an active engagement; NO external refs; NO Indonesian. Run → FAIL. Author (our words). Run → PASS; FULL `bun test`.
- [ ] Commit: `feat(burp): pentest-burp skill + /burp command`

---

### Task 5: REAL e2e — hook enforcement + scope mirror

**Files:** Create `test/burp-guard-e2e.test.mjs`.

**Interfaces produced:** a real, offline, deterministic e2e (spec §7 E2E) — NO Burp needed (drives our real hook + real CLI).

- [ ] Write `test/burp-guard-e2e.test.mjs`: a real temp `--data-dir` engagement (`.active` + a real scope.yaml with an in-scope + out-of-scope domain). Spawn REAL `node hooks/scope-guard.mjs` with a simulated Burp MCP tool-call event on stdin (`{tool_name:"mcp__burp__send_request", tool_input:{url:"http://<out-of-scope>/x"}}`) → assert deny (exit 2) + an `audit.log` DENY line for the Burp target; an in-scope url → allow (exit 0); an event with no active engagement → deny; an unresolvable-target Burp event → deny. Then spawn REAL `node bin/bh-burp-scope.mjs --data-dir <tmp>` → assert a real Burp Target Scope (file/stdout) with the in/out entries. Fail-safe cleanup of the temp dir.
- [ ] Controller RUNS it for real (`bun test test/burp-guard-e2e.test.mjs`). Capture the deny/allow + audit evidence. If blocked, report specifics — do NOT fake.
- [ ] FULL `bun test`.
- [ ] Commit: `test(burp): real e2e — Burp MCP guard denies out-of-scope + scope mirror`

---

### Task 6: README + plugin.json

**Files:** Modify `README.md`, `.claude-plugin/plugin.json`.

- [ ] README: status/roadmap → Phase 8 done; add a **Burp MCP safety** section (Burp runs host-side and bypasses `bh-exec`, so a second PreToolUse choke point scope-checks every Burp MCP call deny-by-default; `bh-burp-scope` mirrors scope into Burp; `/burp`; live drive-through needs Burp Pro — the enforcement is real-tested, the live integration is validated separately). Update `bun test` count; add `src/guard/burp-guard.mjs`, `bin/bh-burp-scope.mjs`, `.claude/skills/pentest-burp/`, `/burp` to Structure. plugin.json description → Phase 8. No external refs, no residual "Fase".
- [ ] FULL `bun test`.
- [ ] Commit: `docs(burp): README Phase 8 Burp MCP safety layer + plugin description`

---

## Self-Review
- Spec coverage: §2→T1, §3→T2, §4→T3, §5→T4, §7 e2e→T5, README→T6. ✅
- No container-tool/catalog/Docker/safety/bh-exec change; guard deny-by-default + fail-closed; reuse matchTarget; existing hook decisions preserved; real hook-enforcement e2e (no Burp needed); English (fix "Fase 0").
- Ordering: T1 (pure guard) → T2 (hook consumes it) → T3 (CLI) → T4 (skill) → T5 (e2e) → T6 (README). T2 edits the merged hook — preserve existing decisions.
