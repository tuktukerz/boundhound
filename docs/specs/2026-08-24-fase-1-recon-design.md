# Design Spec — Phase 1: Recon

**Date:** 2026-08-24
**Status:** draft
**Prerequisite:** Phase 0 + 0.5 merged.
**Guiding principle:** introduce the **first real reconnaissance tools** through the existing safety choke point (`bh-exec` scope + safety + audit, inside the container), producing a **structured attack-surface map** — without weakening any Phase 0 guarantee and without breaking the 108 passing tests.

---

## 1. Goal & Non-Goals

### Goal
Give Boundhound a working recon capability: discover an engagement's attack surface (subdomains → live HTTP services → open ports/services) using real tools, every invocation scope-checked and audited, every tool running only inside the engagement container, and merge the raw outputs into one normalized `recon-map.json`.

### Tool set (v1 — the classic trio)
- **subfinder** — passive subdomain enumeration (target via `-d`).
- **httpx** — HTTP probe + tech/title/status detection (target via `-u`).
- **nmap** — port + service/version scan (bare positional target).

**Deferred to a later phase** (documented, not built now): naabu, katana, masscan, amass, dnsx. v1 proves the pipeline end-to-end with three tools that cover the recon kill-chain; breadth is added later.

### Non-Goals (STRICT)
- ❌ No enumeration/exploitation tooling (that's Phase 2/3).
- ❌ No change to the deny-by-default / fail-closed enforcement *decision* — only new tool entries + two backward-compatible extensions to how a command line is *built and value-checked*.
- ❌ No active brute-forcing / fuzzing (no ffuf/gobuster) — recon only.

### Definition of Done
- The three tools are installed in the container image (pinned versions) and declared in `tools-catalog.json`.
- `bh-exec subfinder|httpx|nmap` runs each tool in-container, scope-checked + audited, with the target routed correctly (flag or positional).
- Value-carrying flags needed for recon (`-p <ports>`, `-oG -`) pass the guard **without** opening a target-smuggling hole.
- `bh-recon-map` merges the raw outputs into `engagements/<name>/output/recon/recon-map.json`.
- A `pentest-recon` skill (authored for Boundhound) + `/recon` command orchestrate the flow.
- **REAL e2e**: nmap + httpx run against a **local target container** (deterministic, offline) and their findings appear in `recon-map.json`. Executed for real during the phase, not just written as a skippable test.
- All existing tests still green; new unit tests for every new/changed module.
- README updated in this phase's PR.

---

## 2. Core code changes (both backward-compatible)

Two small extensions are required because the trio have different CLI shapes than `curl` (the only prior tool). Both preserve every existing test and the anti-smuggling guarantee.

### 2.1 `command-builder` — optional `target_flag`

Today `buildCommand` always appends the target as a **bare last positional** (`curl … <url>`, `nmap … <target>` ✓). subfinder/httpx need the target behind a flag (`-d <domain>`, `-u <url>`). Add an optional `command.target_flag`:

```javascript
export function buildCommand(entry, { target, extraArgs = [] } = {}) {
  const tf = entry.command.target_flag ?? null
  const needsTarget = tf != null || (entry.command.positional ?? []).some((p) => p.required)
  if (needsTarget && !target) throw new Error("required target missing")
  const argv = [entry.command.base, ...extraArgs]
  if (target) {
    if (tf) argv.push(tf, target)   // e.g. subfinder -d acme.io
    else argv.push(target)          // e.g. nmap 1.2.3.4   (unchanged path)
  }
  return argv
}
```

- `curl`/`nmap`: no `target_flag` → bare-positional path unchanged → **existing tests pass untouched**.
- The target is STILL threaded through `--target` and scope-checked by `matchTarget` before `buildCommand` is ever reached — `target_flag` only changes how it's *rendered*, never whether it's *checked*.

### 2.2 Catalog flag schema + value-flag validation (anti-smuggling preserved)

Phase 0 closed target-smuggling by requiring **every** `extraArgs` token to be a catalog-declared **flag name**. That rejects value-carrying flags (`-p 22,80` → `22,80` is not a flag → DENY). Recon needs `-p <ports>` and `-oG -`.

Extend the catalog flag entry with `takes_value` + `value_pattern`:

```jsonc
{ "name": "-p",  "takes_value": true, "value_pattern": "^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$", "description": "port spec" }
{ "name": "-oG", "takes_value": true, "value_pattern": "^-$", "description": "grepable output to stdout" }
{ "name": "-sV", "description": "service/version detection" }   // boolean flag: no takes_value
```

New `extraArgs` walk in `bin/bh-exec.mjs` (replaces the current per-token set check):

```javascript
const flagByName = new Map((entry.command.flags ?? []).map((f) => [f.name, f]))
for (let i = 0; i < extraArgs.length; i++) {
  const tok = extraArgs[i]
  const f = flagByName.get(tok)
  if (!f) return deny(`extraArgs undeclared token '${tok}' (not a declared flag for '${tool}')`)
  if (f.takes_value) {
    const val = extraArgs[i + 1]
    if (val === undefined) return deny(`flag '${tok}' expects a value but none given`)
    if (!f.value_pattern || !new RegExp(f.value_pattern).test(val)) {
      return deny(`value '${val}' for '${tok}' fails value_pattern`)
    }
    i++ // consume the validated value; it is NOT re-checked as a flag
  }
}
```

**Anti-smuggling invariant (unchanged guarantee):** a bare hostname/URL in `extraArgs` is neither a declared flag nor a legal value (a value is only consumed immediately after a `takes_value` flag, and constrained by `value_pattern`). Every `value_pattern` for recon is a **tight character class that cannot express a host** (`-p` = digits/commas/dashes only; `-oG` = literally `-`). So the only route a target can reach a tool is still `--target` → `matchTarget`.

**Catalog loader hardening:** `validateEntry` must reject a flag that is `takes_value: true` but has no `value_pattern` (fail-closed — an unconstrained value flag would reopen smuggling). Add a test.

### 2.3 `safety-check` — recon DoS enrichment (defense-in-depth)

The `extraArgs` allowlist already blocks anything not declared, but `block_dos` is the documented DoS gate and must independently catch aggressive scanning even if a future catalog entry is loosened. Add nmap-shaped rules to `src/safety/safety-check.mjs`:

- Deny `-T5` (insane timing). Allow `-T0`..`-T4` (T4 is normal for authorized scans).
- Deny `--min-rate` / `--max-rate` above a cap (e.g. 5000) — same three forms already handled for `-t`/`--threads`/`--rate` (spaced, `=`, glued).

Keep all existing rules. This is additive.

### 2.4 `recon-map` synthesizer + nmap grepable parser

New `src/recon/recon-map.mjs` — **pure functions** (take raw text, return objects; no I/O), so they unit-test with fixtures:

- `parseSubfinderJsonl(text) -> string[]` — one JSON object per line, collect `.host`.
- `parseHttpxJsonl(text) -> [{ url, host, status_code, title, tech }]`.
- `parseNmapGrepable(text) -> [{ host, ports: [{ port, proto, state, service }] }]` — parse `-oG` lines (`Host: <ip> (<name>)\tPorts: 22/open/tcp//ssh///, …`). Regex-based; **no XML dependency** (that's why we use `-oG -`, not `-oX -`).
- `buildReconMap({ subfinderJsonl, httpxJsonl, nmapGrepable }, { now }) -> { generated_at, subdomains, http_services, hosts }`.

Thin CLI `bin/bh-recon-map.mjs`: reads `engagements/<active>/output/recon/{subfinder.jsonl,httpx.jsonl,*.gnmap}` (via `dataRoot()`/`--data-dir`, same convention as the other bins), writes `recon-map.json`. It is **not** a network tool → runs as plain `node bin/bh-recon-map.mjs …` (the guard allows node without `-c/-e`); it never touches the network, only merges files.

---

## 3. Container image (`docker/Dockerfile`) — multi-stage, pinned

subfinder + httpx are Go binaries; nmap is in apt. Use a builder stage so the final image stays slim and the build is **arch-agnostic** (Go cross-compiles for the native arch; no per-arch release-URL juggling):

```dockerfile
# --- builder: compile the Go recon tools at pinned versions ---
FROM golang:1.23-bookworm AS gotools
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9

# --- final: slim runtime with nmap + bridge utils + the Go binaries ---
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl iputils-ping dnsutils ca-certificates nmap \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gotools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gotools /go/bin/httpx    /usr/local/bin/httpx
# Phase 1: recon tools only (subfinder/httpx/nmap). No enum/exploit tooling yet.
WORKDIR /work
CMD ["sleep", "infinity"]
```

(Versions are examples — the implementer pins to the latest stable release tags at build time and records them.) Image size grows (nmap + two Go binaries) but the builder stage is discarded.

---

## 4. `tools-catalog.json` entries (shape)

Add three entries beside `curl`, following the `ToolEntry` schema (+ the new `target_flag` / `takes_value` / `value_pattern` fields). Illustrative flag sets:

- **subfinder** — `target_flag: "-d"`, flags: `-silent`, `-json`. phase `["recon"]`. (passive; safe.)
- **httpx** — `target_flag: "-u"`, flags: `-silent`, `-json`, `-td` (tech-detect), `-title`, `-sc` (status-code). phase `["recon"]`.
- **nmap** — no `target_flag` (bare positional), flags: `-sT` (connect scan, rootless), `-sV`, `-Pn`, `-T3`, `-T4`, `-p` (value: port pattern), `-oG` (value: `^-$`). phase `["recon"]`, `requires_root: false`.

Only flags Boundhound actually orchestrates are declared — the allowlist stays tight.

---

## 5. `pentest-recon` skill (authored) + `/recon` command + output layout

Per the locked skill strategy (**"reference topics, author our own"**): the skill is **written from scratch for Boundhound**, using the standard Claude Code skill format (frontmatter + markdown playbook). No third-party skill text is copied into the repo.

**`.claude/skills/pentest-recon/SKILL.md`** orchestrates, all via `bh-exec`:
1. Require an active engagement with `in_scope.domains`. To probe discovered subdomains, the engagement must list `*.<domain>` in `in_scope` (matcher does suffix match on `*.` rules, exact otherwise) — the skill states this explicitly and refuses to probe hosts that don't clear scope.
2. **subfinder** (passive) → `output/recon/subfinder.jsonl`. (Needs outbound DNS/internet; documented.)
3. **httpx** on the root domain + each in-scope discovered subdomain → append `output/recon/httpx.jsonl`.
4. **nmap** (`-sT -sV -Pn -T3 -oG -`) on each live host from httpx → `output/recon/<host>.gnmap`.
5. **bh-recon-map** → `output/recon/recon-map.json`.

**`.claude/commands/recon.md`** (`/recon`): load + follow `pentest-recon` against the active engagement.

**Output layout:** `engagements/<name>/output/recon/{subfinder.jsonl, httpx.jsonl, <host>.gnmap, recon-map.json}`. Tools write to stdout; the host shell redirects `bh-exec` stdout into these files (redirection is host-side and does not change the guard's classification — the base command is still `bh-exec`).

---

## 6. Safety analysis (what's newly possible, how it's bounded)

| New capability | Bound |
|---|---|
| Active port scanning (nmap) | Only against `--target` that clears `matchTarget`; `-T5` and high `--min-rate`/`--max-rate` denied by `safety-check`; connect-scan (`-sT`, rootless) default |
| HTTP probing (httpx) | scope-checked target; passive-ish, no fuzzing flags declared |
| Subdomain discovery (subfinder) | passive (queries public sources); discovered hosts still must clear scope before httpx/nmap touch them |
| Value flags (`-p`, `-oG`) | tight `value_pattern`; cannot encode a host → no target-smuggling |
| New tools reachable directly in Bash | already denied by `guard.mjs` NETWORK_BINS (subfinder/httpx/nmap already listed) |

All three tools still run **only** inside the engagement container via `docker exec bh-<engagement>`, never on the host.

---

## 7. English hygiene (fold into this phase — files touched anyway)

Replace remaining non-English text in files this phase edits: the Indonesian comments in `docker/Dockerfile` and `src/safety/safety-check.mjs`; the Indonesian in `.claude/commands/{mode,engagement}.md`; and the `authorization` placeholder comment in `engagements/templates/scope.yaml`. (Full translation of the legacy Phase 0 spec/plan docs remains a separate tracked follow-up.)

---

## 8. Acceptance criteria (DoD tests)

| # | Test | Expect |
|---|---|---|
| R1 | `buildCommand` with `target_flag: "-d"` emits `[base, …extra, "-d", target]`; without it, bare positional (curl/nmap unchanged) | correct render, existing tests untouched |
| R2 | value-flag walk: `-p 22,80` ALLOWs (value matches pattern); `-p evil.com` DENYs; `-p` with no value DENYs; `-oG -` ALLOWs | anti-smuggling preserved |
| R3 | catalog loader rejects a `takes_value` flag lacking `value_pattern` | fail-closed |
| R4 | `safety-check` denies `-T5` and `--min-rate 100000`; allows `-T4`, `-p 1-1000` | DoS bounded |
| R5 | `recon-map` parsers: subfinder/httpx JSONL + nmap grepable fixtures → correct normalized `recon-map` object | correct merge |
| R6 | full `bun test` green (regression: all Phase 0/0.5 tests still pass) | 108+ pass |
| E2E | **REAL:** build image; start a local target container (a known service, e.g. nginx :80) on a docker network; create an engagement with that target in-scope; run `bh-exec nmap`/`bh-exec httpx` against it via real subprocess; `bh-recon-map` produces `recon-map.json` listing port 80 / the HTTP service. Out-of-scope target still DENYs. | real findings, real audit, offline & deterministic |

subfinder's live-network run is covered at unit level (fixture parse) + a container presence check (`subfinder -version`), since real passive enumeration needs internet and is non-deterministic; documented, not asserted in the offline e2e.

---

## 9. Deferred / out of scope
- naabu, katana, masscan, amass, dnsx (breadth) — later phase.
- Feeding httpx a host **list** (`-l`) in one call — v1 runs per-host through the single-`--target` model; batch input is a later optimization.
- `rate_limit` enforcement (still parsed-only).
- Renaming `fase-*` spec/plan filenames to English — tracked English-hygiene follow-up.
