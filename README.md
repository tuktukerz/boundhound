# Boundhound

**An autonomous penetration-testing framework for Claude Code — with scope safety that's _enforced_, not requested.**

Boundhound runs a whole engagement from one command — reconnaissance → enumeration → bounded exploitation → verification → reporting — while making it **technically impossible for the agent to touch a target outside your authorized scope.** Enforcement lives in a git-tracked hook and a CLI choke point the agent doesn't control, so scope holds even if the model is confused, jailbroken, or wrong. Most "AI pentest" tools _ask_ the agent to stay in scope; Boundhound removes the choice.

---

## What you get

- **🎯 One-command engagements** — `/fullscan` chains recon → enum → exploit → verify → report autonomously, then hands you a submittable `report.md`. Or drive each phase by hand (`/recon`, `/enum`, `/exploit`, `/verify`, `/report`).
- **🛡️ Enforced deny-by-default scope** — every tool call passes through one choke point (`bh-exec`) that checks it against `scope.yaml` and refuses anything out of scope, before a packet leaves. A `PreToolUse` hook blocks any attempt to bypass it.
- **🧨 Bounded exploitation** — sqlmap runs in strict proof-of-vulnerability mode; its data-dump, OS-shell, and file-read/write flags are hard-denied by two independent layers before the tool ever starts.
- **♻️ Resilient autonomous scanning** — a long run survives interruption (`--resume`), retries transient tool failures with the identical bounded command (`--max-retries`), and honors a hard step ceiling (`--max-steps`). A scope/safety denial is never retried.
- **🔌 A second choke point for Burp Suite** — Burp runs host-side and its MCP calls bypass the container, so a dedicated guard scope-checks every Burp request deny-by-default and mirrors your scope into Burp's own Target Scope.
- **📚 An 81-skill technique library** — self-authored playbooks across 11 categories (web injection, access control, auth/session, API, recon/OSINT, infra, info-disclosure, business-logic, methodology), each wired to Boundhound's tools and safety model. See [`skills-library/`](skills-library/).
- **🧾 Everything audited** — every tool run and every denial lands in a per-engagement `audit.log`, so an engagement has a complete chain of custody.

## Capabilities at a glance

| Area | Tools / commands | Bound |
|---|---|---|
| Recon | subfinder · httpx · nmap — `/recon` | deny-by-default scope; nmap non-aggressive |
| Enumeration | ffuf · nuclei — `/enum` | concurrency & rate caps |
| Exploitation | sqlmap — `/exploit` | proof-of-vuln only; weaponizing flags denied |
| Verification | `/verify` | re-runs the SAME bounded check, never escalates |
| Reporting | `/report` | pure renderer; never fabricates a finding |
| Orchestration | `/fullscan` | chains all phases; `--resume` / retry / budgets |
| Burp Suite | `/burp` · `bh-burp-scope` | separate deny-by-default MCP choke point |

Every one of those runs through the same enforced `bh-exec` choke point (or, for Burp, its dedicated guard) — the framework can't do anything a manually-run, scope-checked command couldn't.

**Status:** the full pipeline is shipped and green — foundation & safety, plugin packaging, recon, enumeration, bounded exploitation, verification, reporting, the `/fullscan` orchestrator, resilience, and the Burp MCP safety layer are all built, tested, and merged, alongside the 81-skill technique library. It was built **safety-first, one milestone at a time** — every offensive tool was added only after the safety layer bounding it was proven by automated tests ("fences first, weapons later"). Each capability is detailed in its own section below; the phase-by-phase design story and roadmap live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

**Honest about the bounds:** exploitation is proof-of-vulnerability, not weaponization; Boundhound does not drive a Burp scan on its own yet (it enforces the safety layer around Burp MCP, which is validated separately against Burp Pro); and it does not perform mass/credential-flood or denial-of-service attacks — its safety layer caps request rates and denies DoS-shaped activity. It is built for authorized engagements, bug-bounty programs, and your own lab.

## Why this exists

An autonomous pentest agent is dangerous without hard limits. Most "AI pentest" tools rely on the agent *choosing* to respect scope — that's a request, not enforcement. Boundhound inverts that: **the agent is technically unable** to touch out-of-scope targets, because enforcement lives in a layer the agent doesn't control (a git-tracked hook + a CLI choke point), not in a prompt.

## How the safety works

```
User / Agent
    │
    ▼
┌─────────────────────────┐   direct command to curl/nmap/etc?
│  PreToolUse hook         │──────────────► DENY (bypass blocked)
│  (scope-guard.mjs)       │
└─────────────────────────┘
    │ passes through bh-exec
    ▼
┌─────────────────────────┐   target outside scope.yaml?
│  bh-exec                │──────────────► DENY + audit log
│  (choke point)           │
│  scope → safety → audit  │
└─────────────────────────┘
    │ ALLOW
    ▼
┌─────────────────────────┐
│  docker exec             │  tool runs in an isolated container
│  (bh-<engagement>)      │
└─────────────────────────┘
```

- **Deny-by-default** — a target not explicitly listed in `in_scope` is rejected. When in doubt, rejected.
- **Fail-closed** — a broken `scope.yaml` or no active engagement means everything is rejected.
- **`out_of_scope` wins** over `in_scope` — explicit exclusions always take priority.
- **Two independent layers** — the hook stops the agent from *avoiding* `bh-exec`; `bh-exec` itself does the real check.
- **Full audit trail** — every decision (ALLOW/DENY) is logged: timestamp, target, tool, reason, authorization.

All of this is verified by [`test/acceptance.test.mjs`](test/acceptance.test.mjs) and [`test/plugin-e2e.test.mjs`](test/plugin-e2e.test.mjs) — not a claim, there's proof:

```bash
bun test   # 1340 pass · 1 skip (Docker smoke, needs a live container) · 0 fail
```

## Recon

Phase 1 chains three tools against the active engagement's in-scope
targets, orchestrated by the self-authored `pentest-recon` skill (run via
`/recon`):

1. **`subfinder`** — passive subdomain discovery against the in-scope root domain.
2. **`httpx`** — HTTP probing (status code, title, tech detection) of the root domain and any discovered subdomain that clears scope.
3. **`nmap`** — port and service/version scanning of every live host `httpx` found.

Every one of those three invocations goes through `bh-exec` exactly like
any other tool — scope-checked, safety-capped, audited, and run inside the
engagement's container. Nothing in recon gets a shortcut around the choke
point proven in Phase 0.

A final step, `bh-recon-map` (`bin/bh-recon-map.mjs`), reads the raw
`subfinder`/`httpx`/`nmap` output already on disk and normalizes it into
one `recon-map.json`, written to
`engagements/<name>/output/recon/recon-map.json`.

**Probing a discovered subdomain requires opting in to it in scope.**
`subfinder` will often discover subdomains that were never typed into
`scope.yaml` directly. A literal entry like `acme.io` matches only that
exact host — it does not cover `api.acme.io`. To let `httpx`/`nmap` touch
subdomains `subfinder` discovers under `acme.io`, `in_scope.domains` must
explicitly include a wildcard entry, e.g. `"*.acme.io"`. Without it, recon
still records every discovered subdomain in `subfinder.jsonl`, but does not
probe or scan any of them.

This is proven by a real, non-mocked end-to-end test —
[`test/recon-e2e.test.mjs`](test/recon-e2e.test.mjs) — which spins up an
actual local target container and runs the real `nmap`/`httpx` binaries
against it through `bh-exec`, driving the actual CLIs exactly as an
operator would.

## Enumeration

Phase 2 deepens what recon already found, orchestrated by the
self-authored `pentest-enum` skill (run via `/enum`):

1. **`ffuf`** — web content discovery (wordlist-driven directory/file
   fuzzing) against every live HTTP service `httpx` found in recon.
2. **`nuclei`** — templated detection of known vulnerabilities,
   misconfigurations, and technologies against the same hosts.

Both go through `bh-exec` exactly like every other tool in this system —
scope-checked, safety-capped, audited, and run inside the engagement's
container. Enum never gets a shortcut around the choke point proven in
Phase 0, and it never invents its own target list: it consumes the
`recon-map.json` recon already wrote (re-screening each host against the
engagement's *current* scope before touching it), and refuses to run at
all if that file doesn't exist yet.

A final step, `bh-enum-map` (`bin/bh-enum-map.mjs`), reads the raw
`ffuf`/`nuclei` output already on disk and normalizes it into one
`enum-map.json`, written to
`engagements/<name>/output/enum/enum-map.json`.

**The DoS caps are load-bearing here, not decorative.** ffuf and nuclei
are both high-volume by design — a wordlist fuzz run or a template scan
can fire hundreds of requests per second — so `safety-check` enforces caps
on ffuf's thread count and nuclei's template concurrency and request rate,
independently of whatever flags a skill or operator asks for. This is
where those caps actually matter, unlike the lighter-weight Phase 1 tools.

This is proven by a real, non-mocked end-to-end test —
[`test/enum-e2e.test.mjs`](test/enum-e2e.test.mjs) — which spins up an
actual local target container and runs the real `ffuf`/`nuclei` binaries
against it through `bh-exec`, exactly as `recon-e2e.test.mjs` does for
Phase 1.

## Exploitation

Phase 3 confirms a vulnerability recon/enum already surfaced, orchestrated
by the self-authored `pentest-exploit` skill (run via `/exploit`), using
**`sqlmap`** — and only `sqlmap` — run through `bh-exec` exactly like every
other tool in this system. It consumes both `recon-map.json` and
`enum-map.json` (re-screening every candidate host against the engagement's
*current* scope before touching it) and refuses to run at all if either map
doesn't exist yet — exploit never derives its own target list.

**This phase confirms; it does not weaponize.** sqlmap runs in a strictly
bounded proof-of-vulnerability mode: it confirms a SQL-injection point is
real, identifies the DBMS, and recovers database *names* as proof. It
**never dumps table contents, never opens an OS or SQL shell, never reads
or writes a file on the target, and never runs an arbitrary OS/SQL command
or Python `--eval`.** sqlmap's own flags for all of that
(`--dump`/`--dump-all`, `--os-shell`/`--os-pwn`/`--os-cmd`,
`--sql-shell`/`--sql-query`, `--file-read`/`--file-write`/`--file-dest`,
`--reg-*`, `--priv-esc`, `--msf-path`, `--os-smbrelay`, `--eval`,
`--os-bof`) are denied outright, by **two independent layers**:

1. **The catalog allowlist.** `tools-catalog.json`'s sqlmap entry declares
   only the bounded/proof flags (`-p`, `--data`, `--level`, `--risk`,
   `--dbms`, `--technique`, `--threads`, `--timeout`, `--batch`, `--dbs`,
   `--current-db`, `--current-user`, `--banner`, `--is-dba`, `--hostname`)
   — every weaponizing flag above is deliberately left undeclared, so
   `bh-exec`'s extra-args allowlist rejects it as an unrecognized token
   before a command is even built.
2. **`safety-check`'s `block_destructive` gate**, independently of the
   catalog, matches and denies the same flags outright — and caps
   `--level`/`--risk` at ≤3/≤2 whenever `block_dos` is on, so even an
   allowed scan can't escalate into destructive payload territory.

Either layer alone stops weaponization; both hold at once, so a mistake in
one doesn't reopen it.

A final step, `bh-exploit-map` (`bin/bh-exploit-map.mjs`), reads the raw
`sqlmap` stdout captures already on disk and normalizes them into one
`exploit-map.json`, written to
`engagements/<name>/output/exploit/exploit-map.json`.

This is proven by a real, non-mocked end-to-end test —
[`test/exploit-e2e.test.mjs`](test/exploit-e2e.test.mjs) — which spins up
an actual local, deliberately-vulnerable SQL-injection target container and
drives the real `bh-exec.mjs`/`bh-exploit-map.mjs` CLIs against it, proving
**both halves of the safety story in one real run**: sqlmap genuinely
confirms a SQL-injection point (DBMS SQLite) and the result lands in
`exploit-map.json`, *and* `--os-shell`/`--dump` are hard-denied (exit code
2, audit-logged) before sqlmap ever runs them — exactly as
`recon-e2e.test.mjs`/`enum-e2e.test.mjs` do for their own phases.

## Verification

Phase 4 adds no new attack tool. Orchestrated by the self-authored
`pentest-verify` skill (run via `/verify`), it does two things: **consolidate**
and **re-verify**.

1. **Consolidate.** `bh-findings` (`bin/bh-findings.mjs`) reads whichever of
   `recon-map.json`, `enum-map.json`, and `exploit-map.json` already exist
   for the active engagement and normalizes every entry — open ports, live
   HTTP services, discovered subdomains/content, nuclei matches, confirmed
   SQL-injection points — into one `findings.json`, written to
   `engagements/<name>/output/verify/findings.json`. Each finding gets a
   stable, deterministic id (a hash of category/type/target/key, not a
   timestamp or random value), a severity (recon/enum observations are
   `info`; nuclei carries its own severity; a confirmed sqli finding is
   always `high`), and de-duplication — the same underlying issue reported
   more than once collapses to a single finding at its highest observed
   severity, instead of being counted twice.

2. **Re-verify.** For every candidate that isn't already verified,
   `pentest-verify` re-screens its target against the engagement's
   *current* scope and then re-runs that finding's own **same bounded
   check** — the identical tool, target, and already-cataloged flags that
   produced it — through `bh-exec`: a narrower nuclei re-fire of just the
   one template that matched, an httpx re-probe of the exact URL, or an
   nmap re-scan of the exact host/port. **Never escalated** — no wider port
   range, no higher concurrency, no new flag — and **sqlmap is never
   re-run**: a sqli finding is already `verified:true` the moment
   `pentest-exploit` confirmed it, since exploit's proof-of-vulnerability
   run already *is* the verification. Recheck output lands under
   `output/verify/recheck/`, and a second `bh-findings` pass folds it back
   in, flipping `verified` to `true` (and `confidence` to `"confirmed"`)
   wherever the check reproduced.

**A finding that no longer reproduces is kept, never dropped** — it stays
in `findings.json` flagged `verified: false`, because "this no longer
reproduces" (already fixed, or transient) is itself useful signal, not
noise to discard.

This is proven by a real, non-mocked end-to-end test —
[`test/verify-e2e.test.mjs`](test/verify-e2e.test.mjs) — which runs a real
nuclei scan to produce a `verified:false` candidate finding, then drives a
second real nuclei re-fire against the same target through the actual
`bh-exec.mjs`/`bh-findings.mjs` CLIs and confirms the finding flips to
`verified:true` in `findings.json`; a separate case in the same suite
points the re-check at an out-of-scope target and confirms `bh-exec` DENYs
it (exit code 2, audit-logged) before nuclei ever runs — exactly the same
scope enforcement proven for every earlier phase.

## Reporting

Phase 5 adds no new attack tool and makes no network call at all.
Orchestrated by the self-authored `pentest-report` skill (run via
`/report`), **`bh-report`** (`bin/bh-report.mjs`) reads the active
engagement's already-consolidated `output/verify/findings.json` plus its
`scope.yaml` metadata (and a best-effort ALLOW/DENY tally from
`audit.log`), and renders all of it into one markdown document,
`output/report/report.md`.

The rendering itself lives in a **pure** function, `buildReport`
(`src/report/report.mjs`) — no filesystem or network I/O, so the same
`findings` + `meta` + `now` always produces byte-identical output, and it
is unit-tested purely against fixtures. The CLI owns all the I/O: reading
`findings.json`, loading `scope.yaml` through the same `parseScope` every
other phase uses, and writing the result.

The report has:

1. **Title and metadata** — engagement name, authorization on record,
   mode, scope enforcement.
2. **Executive summary** — a severity-count table (critical → info) and
   how many findings are independently verified.
3. **Scope** — in-scope/out-of-scope domains and CIDRs, straight from
   `scope.yaml`.
4. **Methodology** — the recon → enum → exploit → verify workflow, and a
   note that every tool invocation in every phase ran through the enforced
   `bh-exec` choke point.
5. **Findings, grouped by severity** (critical → info; empty severities are
   skipped) — each finding shows its target, confidence, verified status,
   evidence, and **per-type remediation guidance** (a table-driven lookup
   for `sqli`/`nuclei`/`open-port`/`http-service`/`content`/`subdomain`,
   falling back to a generic vulnerability-management line for any
   unrecognized type).
6. **Appendix** — an ALLOW/DENY audit-log summary and a pointer to the raw
   tool output under `output/`.

**It renders only verified engagement data and never fabricates.** Every
fact in the report — every finding, severity, and piece of evidence —
comes straight from `findings.json` and `scope.yaml` exactly as those
files already stand; a missing or unrecognized field renders as an
explicit placeholder, never a guessed value, and an engagement with no
findings yet gets a valid, truthful "no findings recorded" report instead
of invented content.

**`bh-report` fail-closes on a broken scope.** Loading `scope.yaml`
through `parseScope` can throw — a missing engagement/authorization field,
an invalid `scope_enforcement` value, a malformed CIDR, and so on. When
that happens, `bh-report` refuses to write a report at all and exits code
3, the same deny-by-default posture every other phase uses for a broken
scope.

**Markdown only in this phase** — no HTML or PDF output, and no CVSS
scoring; the counts and severities are exactly what `findings.json`
already carries.

This is proven by a real, non-mocked end-to-end test —
[`test/report-e2e.test.mjs`](test/report-e2e.test.mjs) — which seeds a
temp engagement's recon/enum/exploit maps via the real
`buildReconMap`/`buildEnumMap`/`buildExploitMap` builders, then drives the
real `bh-findings.mjs` → `bh-report.mjs` CLI chain as actual subprocesses
and asserts the produced `report.md`'s content (metadata, severity counts,
per-finding sections, remediation text); a second case in the same suite
points at a broken `scope.yaml` and confirms `bh-report` fails closed
(exit code 3, no `report.md` written) before it ever reads findings.

## Orchestration (`/fullscan`)

Phase 6 adds no new attack tool. Orchestrated by the self-authored
`pentest-workflow` skill (run via `/fullscan`), **`bh-fullscan`**
(`bin/bh-fullscan.mjs`, driven by the pure planner/driver in
`src/orchestrate/fullscan.mjs`) chains the entire engagement in one pass —
**recon (subfinder → httpx → nmap) → enum (nuclei → ffuf) → exploit
(sqlmap) → findings → report** — so the operator doesn't have to run
`/recon`, `/enum`, `/exploit`, `/verify`, and `/report` by hand, one at a
time.

**Every tool step still goes through `bh-exec` — the same choke point,
with no shortcut.** `bh-fullscan` never runs `subfinder`, `httpx`, `nmap`,
`nuclei`, `ffuf`, or `sqlmap` directly; each one is dispatched through
`bh-exec` exactly as a manual phase command would — scope-checked,
safety-capped, audited, and run inside the engagement's container. The
orchestrator adds no new capability and no new attack surface on top of
that: it cannot exceed any per-phase bound that already applies when a
human runs one phase at a time, because it is calling the exact same
`bh-exec`-gated commands those phases call. A step `bh-exec` denies (out of
scope, an unsafe flag value, a cap exceeded) is **skipped, not forced** —
`bh-fullscan` never retries a denied step with a different target or a
weaker flag set, and a single denial never aborts the rest of the run.

**Target derivation is in-scope-only.** Each stage re-derives its target
list from whatever the previous stage's map (`recon-map.json` /
`enum-map.json`) already recorded, filtering every candidate through the
same `matchTarget` scope check every other phase uses before it is ever
handed to `bh-exec` — which then re-checks that exact same target
independently, on every call. Neither layer alone is treated as
sufficient, and a discovered host that doesn't clear scope is never
touched.

`bh-fullscan` runs the bounded exploit stage by default. Pass
**`--no-exploit`** for a non-intrusive run that stops after enumeration —
recon and enumeration still run in full, `sqlmap` is never invoked, and the
final report is built from whatever recon and enum found.

**`bh-fullscan` fail-closes on a broken or absent scope.** No active
engagement, or a `scope.yaml` that fails to load, means the CLI exits code
3 and runs nothing at all — no tool step, no map, no report — the same
deny-by-default posture every other phase uses for a broken scope.

A final pair of steps mirrors what a human operator would run last:
`bh-findings` consolidates every map into `findings.json`, then `bh-report`
renders the final `engagements/<name>/output/report/report.md`.

This is proven by a real, non-mocked end-to-end test —
[`test/fullscan-e2e.test.mjs`](test/fullscan-e2e.test.mjs) — which spins up
an actual local target container (nginx) on a real docker network and
drives the real `node bin/bh-fullscan.mjs --data-dir <tmp> --no-exploit`
CLI against it, proving the whole staged pipeline (scope-check →
recon:subfinder/httpx/nmap → enum:nuclei/ffuf → findings → report) end to
end against a live target, with every tool step still going through the
same enforced `bh-exec` choke point — exactly as `recon-e2e.test.mjs` /
`enum-e2e.test.mjs` / `exploit-e2e.test.mjs` / `verify-e2e.test.mjs` /
`report-e2e.test.mjs` do for their own phases, but here proving a single
command really does drive an autonomous scan from recon through to a
written report.

**Resilience: `--resume`, `--max-retries`, `--max-steps`.** Phase 7 adds no
new attack tool and changes nothing about what any individual step is
allowed to do — it only makes a long-running `bh-fullscan` more resilient to
interruption and transient tool failure.

- **`--resume`** continues an interrupted scan instead of starting over: a
  plain state file, `engagements/<name>/output/fullscan-state.json`, records
  which stage/tool/target steps already completed, and re-running the same
  command with `--resume` skips every step already marked done and picks up
  from wherever the run stopped.
- **`--max-retries N`** (default `0`, opt-in) retries a **transient** tool
  failure — a crash, a network blip, any non-zero exit that isn't a
  scope/safety DENY — up to `N` times, with a bounded backoff between
  attempts. Every retry re-runs the **identical bounded `bh-exec` command**:
  same tool, same target, same flags already dispatched the first time — it
  never relaxes a bound, widens a target, or otherwise "tries harder." A
  scope/safety **DENY is never retried**: it's a final decision, not a
  transient failure, so it is skipped exactly as before `--max-retries`
  existed.
- **`--max-steps N`** / **`--max-steps-per-stage N`** cap the whole run /
  a single stage at a hard number of tool steps. Both are safety-positive
  bounds — they only ever **reduce** how much autonomous work a run
  performs, never expand it; the run still finishes findings + report from
  whatever it collected before the budget was hit. Omitting all three flags
  runs exactly as Phase 6 already did.

This is proven by a real, non-mocked end-to-end test —
[`test/fullscan-resilience-e2e.test.mjs`](test/fullscan-resilience-e2e.test.mjs)
— which runs a real `bh-fullscan.mjs --resume` against a live target
container, interrupts it partway through, then re-runs the identical
`--resume` command and confirms the already-completed steps are skipped
rather than re-executed, end to end.

## Burp MCP safety

Every tool discussed above runs *inside* the engagement container and is
invoked by Boundhound itself through `bh-exec` — the choke point sees the
command, checks scope, applies safety caps, and audits it. **Burp Suite is the
exception.** Burp runs on the operator's host machine (Burp **Pro** for active
scan), not in the container, and when it's connected over MCP it sends its own
HTTP requests directly to the target. A Burp MCP tool call therefore **never
passes through `bh-exec`** — the Bash-level scope guard can't see it.

Rather than trust Burp to stay in scope, Boundhound adds a **second,
independent choke point** for it:

- **A PreToolUse scope guard for Burp MCP calls.** The guard
  ([`src/guard/burp-guard.mjs`](src/guard/burp-guard.mjs), wired into
  [`hooks/scope-guard.mjs`](hooks/scope-guard.mjs)) intercepts every Burp MCP
  tool call before it runs, extracts its target, and scope-checks it
  **deny-by-default** against the active engagement. A call is denied — and the
  denial written to the engagement audit log — when there is no active scope, an
  unresolvable target, an **ambiguous** target (its candidate fields disagree,
  e.g. an in-scope `url` alongside an out-of-scope `host`), a **suspicious**
  authority (backslash/control-character tricks that a host and Burp might parse
  differently), or a target outside `in_scope`. It reuses the exact same
  `matchTarget` scope logic every other phase uses, so a Burp call can never
  reach a target a `bh-exec` call couldn't.
- **`bh-burp-scope` mirrors `scope.yaml` into Burp's own Target Scope.** Run
  `node bin/bh-burp-scope.mjs` (or `/burp`) to emit a Burp Target Scope
  (`output/burp/target-scope.json`) — `in_scope` as include entries, `out_of_scope`
  as exclude entries, with anchored host regexes — that the operator loads into
  Burp. This is defense in depth: Burp refuses out-of-scope hosts itself, on top
  of the guard.

The enforcement layer — guard, audit, and scope mirror — is live and covered by
a real end-to-end test
([`test/burp-guard-e2e.test.mjs`](test/burp-guard-e2e.test.mjs)) that drives the
actual hook subprocess with real Burp-MCP-shaped events and asserts out-of-scope
is denied + audited while in-scope is allowed. **Actually driving Burp over MCP**
(Repeater/Scanner) requires the operator's Burp Pro and a wired Burp MCP server,
and is validated separately — Boundhound does not itself drive Burp yet. The
`pentest-burp` skill explains the model; `/burp` is the entry point.

## Skill library

Beyond the curated per-phase skills that drive the pipeline, Boundhound ships a broad **technique-playbook library** under [`skills-library/`](skills-library/) — **81 self-authored skills across 11 categories**:

| Category | Skills | Examples |
|---|---|---|
| web-injection | 14 | sqli, xss (reflected/stored/dom), ssrf, ssti, xxe, command-injection |
| recon-osint | 10 | subdomain-enumeration, dns-recon, tech-fingerprinting, port-service-scanning |
| web-auth-session | 9 | auth-bypass, jwt-attacks, oauth-misconfig, mfa-bypass |
| web-access-control | 8 | idor, broken-access-control, path-traversal, lfi/rfi |
| api | 8 | graphql-attacks, mass-assignment, bola/bfla, swagger-openapi-recon |
| web-client | 7 | csrf, cors-misconfig, open-redirect, prototype-pollution |
| infra-network | 7 | smb/snmp/ftp enumeration, ssl-tls-audit, service-version-audit |
| info-disclosure | 7 | exposed-git, backup-file-discovery, source-map-exposure |
| business-logic | 4 | race-condition, workflow-bypass, price-parameter-tampering |
| methodology | 6 | bug-bounty-workflow, recon-methodology, severity-triage, report-writeup |

Each playbook is written from scratch in our own words and **wired to Boundhound's real system** — it names the bounded tool(s) and phase command(s) it uses, and where a technique has no bounded tool yet, it says so and gives the safe, in-scope path rather than implying a capability that doesn't exist. Every skill is machine-validated by `test/skill-library.test.mjs` (valid frontmatter, no external references, English-only, genuine Boundhound wiring). These are **source playbooks** — a coverage map and reference; the active per-phase skills under `.claude/skills/` are promoted deliberately, not auto-loaded.

## Install as a Claude Code plugin

```
/plugin marketplace add tuktukerz/boundhound
/plugin install boundhound@tuktukerz-marketplace
```

Once installed, the **scope-guard hook enforces from any project directory** — you no longer need to be inside this repo checkout for the safety layer to be active. This is a hard guarantee: Claude Code exports `${CLAUDE_PLUGIN_ROOT}` directly to the hook's subprocess environment, and it's proven by `test/plugin-e2e.test.mjs`, which runs the hook from a foreign cwd with nothing pointing at this repo and confirms the DENY + audit trail still land correctly.

`/engagement` and `/mode` are wired the same way — their instructions invoke `node "${CLAUDE_PLUGIN_ROOT}/bin/bh-engagement.mjs" ... --data-dir "${CLAUDE_PLUGIN_DATA}"` rather than a bare relative path — but that convenience path depends on Claude Code resolving both placeholders inline in skill/command content and the agent following the written instruction, which is a documented mechanism but not the same kind of hard runtime guarantee the hook has. See **Known limitations** below.

Engagement state (scope files, `.active`, audit logs) lives under the plugin's own data directory (`${CLAUDE_PLUGIN_DATA}`), so it persists across plugin updates instead of being wiped when the plugin's code is refreshed. The CLI (`bh-exec.mjs` / `bh-engagement.mjs`) receives that path via an explicit `--data-dir "${CLAUDE_PLUGIN_DATA}"` argument, content-substituted the same way `${CLAUDE_PLUGIN_ROOT}` already is in the script path — **not** by reading `CLAUDE_PLUGIN_DATA` as an environment variable at runtime. That distinction matters: Claude Code exports `CLAUDE_PLUGIN_DATA` as a real env var only to hook/MCP/LSP subprocesses, not to the agent's Bash tool session, so a CLI process spawned via Bash never sees it in its own `process.env` — without `--data-dir`, `dataRoot()` would silently fall back to the current working directory instead. Passing it explicitly as a CLI argument is what makes the CLI's state and audit log land in the same directory the hook (which does get the env var) already uses — see `test/plugin-cli-data-dir.test.mjs`.

## Known limitations

- **One active engagement per installation.** Engagement state — including the single `.active` pointer file — lives under one shared `${CLAUDE_PLUGIN_DATA}` directory for the whole plugin installation, not per-project. Treat only one engagement as active at a time. Running different engagements concurrently from different project directories against the same installed plugin is **not yet supported**: they would share `.active` and could misattribute the audit trail (e.g. a tool run kicked off from project B could get logged against project A's engagement). This is a known gap for future work, not a safety bug — the deny-by-default/fail-closed guarantees still hold for whichever engagement is actually active.
- **`/engagement` and `/mode` are agent-instruction-dependent, not hook-enforced.** They rely on the agent following the `${CLAUDE_PLUGIN_ROOT}`/`${CLAUDE_PLUGIN_DATA}`-qualified invocation written into the `pentest-mode` skill and command files (see that skill's "Invoking the scripts" section). The scope-guard hook has no such dependency — it is registered directly with Claude Code and fires unconditionally.

## Run from a clone (dev mode)

The alternative to installing as a plugin: clone the repo and run everything locally, with state kept inside the checkout (`$CLAUDE_PROJECT_DIR`) instead of `${CLAUDE_PLUGIN_DATA}`. Useful for developing Boundhound itself.

```bash
bun install
bun test                        # 1340 pass / 1 skip

bin/bh-container up smoke     # start the tool container
node bin/bh-engagement.mjs acme   # scaffold a new engagement -> fill in scope.yaml
node bin/bh-exec.mjs curl --target api.acme.io -- -I   # run a tool through the choke point
```

In dev mode, omit `--data-dir` entirely — both scripts fall back to `$CLAUDE_PROJECT_DIR`/cwd (see `dataRoot()` in `src/paths.mjs`). `--data-dir <path>` is accepted by both scripts in any mode and, when passed, always wins over the env-var fallback.

## Structure

```
.claude-plugin/
  plugin.json              plugin manifest (skills/commands/hooks entry points)
  marketplace.json         self-hosted marketplace so the repo is /plugin-installable
.claude/
  skills/pentest-mode/     active skill (engagement mode + scope selector)
  skills/pentest-recon/    active skill (Phase 1 recon orchestrator: subfinder -> httpx -> nmap -> bh-recon-map)
  skills/pentest-enum/     active skill (Phase 2 enum orchestrator: ffuf -> nuclei -> bh-enum-map)
  skills/pentest-exploit/  active skill (Phase 3 exploit orchestrator: sqlmap -> bh-exploit-map, bounded proof-of-vuln)
  skills/pentest-verify/   active skill (Phase 4 verify orchestrator: bh-findings -> re-check via bh-exec -> bh-findings)
  skills/pentest-report/   active skill (Phase 5 report orchestrator: bh-report -> read + summarize report.md)
  skills/pentest-workflow/ active skill (Phase 6 fullscan orchestrator: bh-fullscan chains recon -> enum -> exploit -> findings -> report)
  skills/pentest-burp/     active skill (Phase 8 Burp MCP safety model: separate deny-by-default choke point + scope mirror)
  commands/                /engagement, /mode, /recon, /enum, /exploit, /verify, /report, /fullscan, /burp
  settings.json            PreToolUse hook registration (dev/project mode)
bin/
  bh-exec.mjs            choke point: scope + safety + audit -> docker exec
  bh-engagement.mjs      scaffold a new engagement
  bh-recon-map.mjs       merges subfinder/httpx/nmap output into recon-map.json
  bh-enum-map.mjs        merges ffuf/nuclei output into enum-map.json
  bh-exploit-map.mjs     merges sqlmap output into exploit-map.json
  bh-findings.mjs        consolidates recon/enum/exploit maps + verify rechecks into findings.json
  bh-report.mjs          renders findings.json + scope.yaml (+ audit tally) into report.md
  bh-fullscan.mjs        orchestrator CLI: stages recon -> enum -> exploit -> findings -> report through bh-exec; Phase 7 adds --resume (state in output/fullscan-state.json), --max-retries, --max-steps/--max-steps-per-stage
  bh-burp-scope.mjs      mirrors scope.yaml into a Burp Target Scope (output/burp/target-scope.json), fail-closed
  bh-container           Docker container lifecycle
hooks/
  scope-guard.mjs          blocks bh-exec bypass attempts; also the Burp MCP deny-by-default choke point (Phase 8)
  hooks.json               PreToolUse hook registration (plugin mode, ${CLAUDE_PLUGIN_ROOT})
src/
  paths.mjs                code root vs data root resolution (plugin vs local-project)
  scope/                   parser + matcher (deny-by-default) + fail-closed resolver
  safety/                  blocks destructive/DoS actions (incl. ffuf/nuclei concurrency & rate caps, sqlmap weaponizing-flag denial + --level/--risk caps)
  catalog/                 tools-catalog.json loader (ToolEntry schema)
  guard/                   command classification, anti-bypass; burp-guard.mjs: pure Burp MCP scope decision (deny-by-default, fail-closed)
  audit/                   JSONL audit log
  recon/                   recon-map.mjs: normalizes subfinder/httpx/nmap output into recon-map.json
  enum/                    enum-map.mjs: normalizes ffuf/nuclei output into enum-map.json
  exploit/                 exploit-map.mjs: normalizes sqlmap output into exploit-map.json
  verify/                  findings.mjs: consolidates recon/enum/exploit maps + applies re-verification into findings.json
  report/                  report.mjs: pure markdown renderer (findings.json + scope meta -> report.md), no I/O
  orchestrate/             fullscan.mjs: pure planner (in-scope target derivation per stage) + staged driver, no I/O
                           run-state.mjs: pure resume-state model (stepKey/isDone/markDone/parseState/serializeState) backing `--resume`, no I/O
docker/
  Dockerfile               multi-stage image — nmap, subfinder, httpx (Phase 1) + ffuf, nuclei (Phase 2) + sqlmap (Phase 3)
  wordlists/               bundled wordlist for ffuf content discovery
skills-library/            81-skill self-authored technique-playbook library (11 categories); see skills-library/README.md
docs/
  ARCHITECTURE.md          big-picture map & 8 phases
  specs/, plans/           spec & implementation plan per phase
```

## Design principles

1. **Safety before capability.** Every new capability phase (recon, exploit, etc.) is built on a foundation that has already passed its tests — not the other way around.
2. **Skills are authored, not imported.** Each active skill is written for Boundhound's own config and enforcement model, and promoted one phase at a time alongside the tools it orchestrates — never shipped ahead of the safety layer that bounds it.
3. **Enforcement, not instruction.** When something must hold true, it's enforced by code/hooks — not just written into agent instructions.
4. **Every task = TDD + adversarial review.** Built via subagent-driven development: each module is written test-first, reviewed by an independent subagent, and every finding (including real bugs — a guard bypass, a fail-open hook, a dead `import.meta.main` check on Node) is closed with a regression test before moving on.

## Roadmap

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full map of all 8 phases, design decisions, and the reasoning behind each architectural choice.

---

*Built iteratively: brainstorming → grilling → spec → plan → subagent-driven implementation, each step reviewed before moving on.*
