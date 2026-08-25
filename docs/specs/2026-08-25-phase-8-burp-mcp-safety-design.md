# Design Spec — Phase 8: Burp MCP Safety Layer

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0–7 merged.
**Guiding principle:** Boundhound's entire safety model is "every tool step goes through the `bh-exec` Bash choke point, scope-checked deny-by-default." A Burp Suite MCP server breaks that assumption: Burp runs on the host and sends HTTP requests itself, so its MCP tool calls **never pass through `bh-exec`** and are invisible to the existing Bash scope-guard. Therefore, before Boundhound can safely use Burp at all, it needs a **second choke point**: a PreToolUse guard that intercepts every Burp MCP tool call, extracts its target, and scope-checks it against the active engagement (deny-by-default). This phase builds that safety layer — the prerequisite for any Burp use — plus a helper to mirror `scope.yaml` into Burp's own Target Scope (defense in depth) and the operator docs. **Safety before capability**, exactly as every prior phase.

**Environment note (honest scoping):** Burp Suite is not installed on the build host and no Burp MCP server is wired into the session, so the *live drive-through* (actually invoking Burp Repeater/Scanner via MCP) cannot be built against a real schema or proven by a live e2e here — and this project never fakes an e2e. This phase therefore delivers and **really tests the enforcement layer** (our own hook code processing real Burp-MCP-shaped tool-call events), and explicitly defers the live drive-through + final field-name tuning to a later validation against the operator's Burp Pro.

---

## 1. Goal & Non-Goals

### Goal
A Burp MCP scope choke point that is deny-by-default and fail-closed, built as: a **pure guard module** (`src/guard/burp-guard.mjs`), a **wiring** of that module into the existing PreToolUse hook (`hooks/scope-guard.mjs` + `hooks/hooks.json`), a **scope-mirroring CLI** (`bin/bh-burp-scope.mjs`), and a **`pentest-burp` skill + `/burp` command**. Proven by a REAL e2e that drives the actual hook subprocess with simulated Burp MCP tool-call events.

### Non-Goals (STRICT)
- ❌ No new *container* attack tool: Burp runs on the host, so NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, or `bin/bh-exec.mjs`.
- ❌ Not the live Burp drive-through: this phase does NOT invoke Burp; it makes Burp *safe to invoke later*. The MCP server field-names for target extraction are configurable and will be finalized against the real server.
- ❌ The guard NEVER fails open: if it cannot determine an in-scope target for a Burp MCP call (no active engagement, unparseable target, out-of-scope), it DENIES. A false-deny is acceptable; a false-allow is not.
- ❌ No relaxation of any existing guard behavior — the current Bash/WebFetch/Write-Edit decisions are preserved byte-for-byte.

### Definition of Done
- `src/guard/burp-guard.mjs` (pure): `isBurpMcpTool(toolName)`, `extractBurpTarget(toolInput)`, `decideBurpMcp(toolInput, scopeConfig)` — deny-by-default, never throws.
- `hooks/scope-guard.mjs`: `decideFromEvent` routes a Burp MCP tool call through `decideBurpMcp` against the active engagement's parsed scope; a DENY is audited like any other hook DENY. (Also: fix the stray Indonesian "Fase 0" → "Phase 0" in this file.)
- `hooks/hooks.json`: the PreToolUse matcher also catches Burp MCP tool names.
- `bin/bh-burp-scope.mjs`: reads the active engagement's `scope.yaml` and emits a Burp-importable Target Scope (include/exclude) so the operator mirrors scope into Burp itself; fail-closed on a broken/absent scope.
- `pentest-burp` skill + `/burp` command (self-authored, English, no external refs).
- **REAL e2e**: drive `node hooks/scope-guard.mjs` as a subprocess with simulated Burp MCP events (out-of-scope → deny+audit; in-scope → allow; no active engagement → deny; unparseable target → deny) and run `bh-burp-scope` against a real temp engagement. Controller-run.
- All existing tests green; README updated in this phase's PR.

---

## 2. Core: the Burp guard (`src/guard/burp-guard.mjs`, pure)

Deterministic, never-throws.
- `isBurpMcpTool(toolName) -> boolean` — true for an MCP tool name that belongs to a Burp server. MCP tool names are `mcp__<server>__<tool>`; match `^mcp__` AND a case-insensitive `burp` in the name. (Configurable/broadenable, but this default catches the common naming.)
- `extractBurpTarget(toolInput) -> string | null` — pull a target host/URL from the tool arguments, checking, in order, common fields: `url`, `target`, `targetUrl`, `host` (+ optional `port`), then a raw request field (`request`/`httpRequest`/`rawRequest`) by parsing its request-line URL or `Host:` header. Returns `null` if none found. Purely structural; no network.
- `decideBurpMcp(toolInput, scopeConfig) -> { decision: "ALLOW"|"DENY", reason }`:
  - no `scopeConfig` (no active engagement / broken scope) → `DENY "no-active-scope"`.
  - `extractBurpTarget` → `null` → `DENY "burp-target-unresolved"` (fail-closed: can't verify scope ⇒ deny).
  - else → `matchTarget(target, scopeConfig)` (reuse `src/scope/scope-matcher.mjs`) verbatim → its ALLOW/DENY.

## 3. Hook wiring (`hooks/scope-guard.mjs` + `hooks/hooks.json`)
- In `decideFromEvent`, add a branch BEFORE the final `allow`: `if (isBurpMcpTool(event.tool_name)) { load the active engagement's parsed scope (via the same active-engagement/scope-parser path the bins use); return mk(decideBurpMcp(event.tool_input, scope)); }`. Loading scope must be fail-closed (any error → deny). The existing Bash/WebFetch/Write-Edit branches are untouched.
- A Burp MCP DENY is audited by the existing `auditHookDeny` path (extend the `detail` extraction to include the Burp target).
- `hooks/hooks.json`: broaden the PreToolUse `matcher` so Burp MCP tool names reach the hook — e.g. add an alternative that matches `mcp__` Burp tools. The guard itself only *acts* on Burp MCP tools (others fall through to `allow`), so a slightly broad matcher is safe.
- Fix the stray `"(Fase 0)"` wording in the WebFetch/WebSearch deny reason → `"(Phase 0)"` (English-only policy; part of the tracked cleanup, done here since we're editing this file).

## 4. Scope-mirror CLI (`bin/bh-burp-scope.mjs`)
Mirrors the other bins (`--data-dir`, `process.argv[1]`, `dataRoot()`, fail-closed code 3 on no active engagement / broken scope). Reads the active `scope.yaml` via `parseScope` and prints a Burp Suite Target Scope definition (include entries from `in_scope`, exclude entries from `out_of_scope`) in Burp's importable JSON shape, so the operator loads it into Burp (Target → Scope → Load) — a defense-in-depth second fence in Burp itself. Not a network tool; writes nothing (prints to stdout) or writes `output/burp/target-scope.json` (decide in the plan). Deterministic.

## 5. `pentest-burp` skill + `/burp` command
Self-authored, English, no external refs. Documents:
1. Burp runs on the **host** (Burp **Pro** for active scan), not in the container; Burp MCP calls do NOT pass through `bh-exec`.
2. Therefore Boundhound enforces a **separate choke point**: every Burp MCP tool call is scope-checked by the PreToolUse guard, **deny-by-default** — an out-of-scope (or unresolvable) Burp target is denied and audited.
3. The operator MUST ALSO mirror scope into Burp's own Target Scope via `bh-burp-scope` (defense in depth).
4. Requires an active, authorized, in-scope engagement first.
`/burp` mirrors the other commands. `tools:` notes Burp MCP (host); `phase: ["burp"]` (or similar).

## 6. Safety analysis
| Concern | Bound |
|---|---|
| Burp bypasses bh-exec | a dedicated PreToolUse guard scope-checks EVERY Burp MCP tool call, deny-by-default, before it runs |
| Unverifiable target | fail-closed: no active scope / unparseable target ⇒ DENY (never allow what we can't verify) |
| Defense in depth | `bh-burp-scope` mirrors `scope.yaml` into Burp's own Target Scope so Burp also refuses out-of-scope |
| No new container surface | Burp is host-side; NO catalog/Docker/safety-check/bh-exec change |
| Audit | a Burp MCP DENY is written to the engagement `audit.log`, same as any hook DENY |
| Existing guards | Bash/WebFetch/Write-Edit decisions preserved byte-for-byte |

The phase can only ADD denials (a new fence); it cannot allow anything that wasn't already reachable, and it changes nothing about the existing container-tool path.

## 7. Acceptance criteria
| # | Test | Expect |
|---|---|---|
| B1 | `isBurpMcpTool`: true for `mcp__burp__send_request`/`mcp__pro_burp__scan`; false for `Bash`/`mcp__github__x`/`""` | correct match |
| B2 | `extractBurpTarget`: pulls host from `{url}`, `{target}`, `{host}`, and a raw request with a `Host:` header; `null` when absent | correct extraction |
| B3 | `decideBurpMcp`: no scope → DENY; unresolvable target → DENY; out-of-scope url → DENY; in-scope url → ALLOW (reuses matchTarget) | deny-by-default + fail-closed |
| B4 | `decideFromEvent` (hook): a Burp MCP event out-of-scope → deny; in-scope → allow; existing Bash/Write-Edit/WebFetch decisions unchanged | correct routing, no regression |
| B5 | `bh-burp-scope` CLI: temp engagement → emits Burp Target Scope with the in/out entries; broken/absent scope → fail-closed code 3 | correct + fail-closed |
| B6 | `pentest-burp` skill: frontmatter valid; `/burp` command; no external refs; no Indonesian | valid skill |
| B7 | full `bun test` green | 597+ pass |
| E2E | **REAL:** drive `node hooks/scope-guard.mjs` as a subprocess (real stdin event) for a real temp engagement: out-of-scope Burp MCP call → deny (exit 2) + an `audit.log` DENY line; in-scope → allow (exit 0); no active engagement → deny; unresolvable target → deny. Then run real `node bin/bh-burp-scope.mjs` → a real Burp Target Scope file/stdout matching the scope.yaml. Controller-run. (No Burp needed — the hook is our real code.) | real enforcement proven |

---

## 8. Deferred / notes
- **Live Burp drive-through** (invoking Repeater/Scanner via the real MCP server) + finalizing `extractBurpTarget` field-names against that server's actual tool schema + a live scoped e2e → requires the operator's Burp Pro; validated later.
- The PreToolUse **matcher** actually routing real Burp MCP tool names to the hook is an integration point that needs one live confirmation once a Burp MCP server is connected (the decision logic is fully tested here; the Claude-Code matcher↔MCP-tool wiring is the one piece that can't be exercised without a live server).
- Tracked pre-existing follow-ups remain: `fase-*` → `phase-*` filename cleanup (this phase fixes the `hooks/scope-guard.mjs` "Fase 0" string); `now`-non-function throw; safety non-finite numeric cap; CI `bun test` workflow.
