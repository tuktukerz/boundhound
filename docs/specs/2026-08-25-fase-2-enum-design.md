# Design Spec — Phase 2: Enumeration

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0 + 0.5 + 1 merged.
**Guiding principle:** deepen the attack-surface map produced by recon — enumerate **content** (paths/endpoints) and **known issues** (templated vuln/misconfig/tech detection) on the in-scope hosts recon found — through the existing `bh-exec` choke point, with the DoS safety caps now genuinely load-bearing (these are high-volume tools). No exploitation (that is Phase 3).

---

## 1. Goal & Non-Goals

### Goal
Enumerate the recon-discovered surface: brute-force web content with **ffuf**, and detect known vulnerabilities / misconfigurations / technologies with **nuclei** — every invocation scope-checked, safety-capped, audited, and run only in-container — merged into one normalized `enum-map.json` that builds on `recon-map.json`.

### Tool set (v1)
- **ffuf** — web content/directory discovery (FUZZ a wordlist against a URL).
- **nuclei** — templated detection of vulns/misconfigs/tech (community + custom templates).

**Deferred** (documented, not built now): gobuster/feroxbuster (ffuf covers content discovery), whatweb (nuclei tech templates cover it), dnsx (recon-adjacent), wpscan/nikto (later/specialized).

### Non-Goals (STRICT)
- ❌ No exploitation — nuclei runs in **detection** mode; intrusive/DoS template categories are excluded by default and capped by safety. No sqlmap/metasploit/etc.
- ❌ No change to the enforcement *decision* — reuse Phase 1's `target_flag` + value-flag allowlist unchanged. Only new catalog entries, two new safety caps, an enum-map synthesizer, a skill, and image tooling.
- ❌ No unbounded brute force — thread/rate/concurrency are safety-capped; a wordlist is required (no built-in generator).

### Definition of Done
- ffuf + nuclei installed in `bh:base` (pinned), plus a small bundled wordlist; declared in `tools-catalog.json` with **fully-anchored** `value_pattern`s (per the Phase-1 loader invariant).
- `bh-exec ffuf|nuclei` runs in-container, scope-checked (host extracted from the FUZZ/`-u` URL) + audited; the DoS caps deny over-threaded/over-rate runs.
- `bh-enum-map` merges ffuf + nuclei output into `engagements/<name>/output/enum/enum-map.json`.
- `pentest-enum` skill (self-authored) + `/enum` command orchestrate it, consuming `recon-map.json`.
- **REAL e2e**: ffuf finds a known path on a local nginx target; nuclei detects nginx via a **bundled** template (no online template fetch → offline/deterministic); out-of-scope still DENYs. Executed for real by the controller.
- All existing tests green; README updated in this phase's PR.

---

## 2. Core code changes

### 2.1 No pipeline change (reuse Phase 1)
ffuf and nuclei both take their target behind `-u`, so they use the existing `command.target_flag: "-u"`. ffuf's target is a **FUZZ-URL** (`http://<host>/FUZZ`); `normalizeTarget` already extracts the host from a URL (verified: `https://acme.io/FUZZ` → `acme.io`), so scope-checking is unchanged. Their value flags (`-w`, `-mc`, `-t`, `-c`, `-rl`, `-severity`, …) ride the Phase-1 `takes_value`+`value_pattern` allowlist. **No change to `command-builder.mjs` or `bh-exec.mjs`.**

### 2.2 `safety-check` — nuclei volume caps (additive)
The existing DoS rules cap `-t`/`--threads` (500), `--rate` (10000), `--min-rate`/`--max-rate` (5000). ffuf's `-t`/`-rate` are already covered. Add nuclei-shaped caps when `block_dos` is true:
- `-c` / `-concurrency` → max **50** (nuclei template concurrency).
- `-rl` / `-rate-limit` → max **1000** (nuclei requests/sec).
Same spaced / `=value` / (no glued needed for long flags) handling already in the file. Keep all existing rules. This is where the safety layer earns its keep — enum tools are high-volume by nature.

### 2.3 `enum-map` synthesizer (pure functions + CLI)
New `src/enum/enum-map.mjs` — pure, no I/O:
- `parseFfufJson(text) -> [{ url, path, status, length, words, host }]` — ffuf `-of json` emits a JSON object with a `results` array; collect each result's `url`/`input`/`status`/`length`.
- `parseNucleiJsonl(text) -> [{ template_id, name, severity, host, matched_at, type }]` — nuclei `-jsonl` emits one JSON object per finding; tolerate blank/malformed lines (skip, never throw — same discipline as recon-map).
- `buildEnumMap({ ffufJson, nucleiJsonl }, { now } = {}) -> { generated_at, content: [...], findings: [...], by_severity: {info,low,medium,high,critical} }` — `by_severity` counts nuclei findings.
New `bin/bh-enum-map.mjs` — thin CLI mirroring `bin/bh-recon-map.mjs` exactly (`--data-dir` idiom, `process.argv[1]` main-detection, `dataRoot()` fallback). Reads `engagements/<active>/output/enum/{ffuf*.json, nuclei*.jsonl}`, writes `enum-map.json`. Missing inputs treated as empty. Not a network tool.

---

## 3. Container image (`docker/Dockerfile`) — add enum tools + wordlist

Extend the existing multi-stage build. In the `gotools` builder, add pinned installs; in the final stage, copy the binaries and bake a small wordlist:

```dockerfile
# builder (add to existing go install block):
RUN go install github.com/ffuf/ffuf/v2@v2.1.0 \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.0
# final stage:
COPY --from=gotools /go/bin/ffuf   /usr/local/bin/ffuf
COPY --from=gotools /go/bin/nuclei /usr/local/bin/nuclei
# bundled small wordlist (committed under docker/wordlists/common.txt)
COPY wordlists/common.txt /usr/share/boundhound/wordlists/common.txt
```

- **Versions are examples** — the implementer pins to current stable release tags and records them; the controller validates the build resolves (as in Phase 1).
- **Wordlist:** commit a small `docker/wordlists/common.txt` (~50–100 common web paths, MUST include `index.html` so the offline e2e finds a real 200 on nginx). Baked at `/usr/share/boundhound/wordlists/common.txt`.
- **nuclei templates / offline:** nuclei normally downloads its template repo on first run (needs internet). For the **offline, deterministic e2e** we do NOT rely on that: the e2e mounts/copies a **bundled custom template** (a minimal YAML that matches nginx's `Server` header) into the container and runs `nuclei -u http://<host> -t <that-template> -jsonl -disable-update-check`. In real engagements the operator runs nuclei with the full template set (online); the skill documents both.

---

## 4. `tools-catalog.json` entries (shape; all `value_pattern`s fully anchored)

- **ffuf** — base `ffuf`, `target_flag:"-u"` (FUZZ-URL), `phase:["enum"]`, `requires_root:false`. flags:
  - `-w` (takes_value, `^/[A-Za-z0-9._/-]+$` — absolute wordlist path)
  - `-mc` (takes_value, `^[0-9]{3}(,[0-9]{3})*$` — match status codes)
  - `-fc` (takes_value, `^[0-9]{3}(,[0-9]{3})*$` — filter codes)
  - `-t` (takes_value, `^[0-9]+$` — threads; also safety-capped)
  - `-rate` (takes_value, `^[0-9]+$` — req/s; also safety-capped)
  - `-of` (takes_value, `^(json|csv|md|html|ejson)$`), `-o` (takes_value, `^/[A-Za-z0-9._/-]+$`)
  - `-s` (boolean, silent)
- **nuclei** — base `nuclei`, `target_flag:"-u"`, `phase:["enum"]`, `requires_root:false`. flags:
  - `-t` (takes_value, `^[A-Za-z0-9._/-]+$` — template path/dir)
  - `-severity` / `-s`? use `-severity` (takes_value, `^[a-z]+(,[a-z]+)*$`)
  - `-c` (takes_value, `^[0-9]+$` — concurrency; safety-capped 50)
  - `-rl` (takes_value, `^[0-9]+$` — rate-limit; safety-capped 1000)
  - `-jsonl` (boolean), `-disable-update-check` (boolean), `-silent` (boolean), `-nc`? keep minimal.
- Add `"enum"` to top-level `categories`.

Only flags the skill actually orchestrates are declared. Every value flag is anchored (loader enforces this).

---

## 5. `pentest-enum` skill (self-authored) + `/enum` command + output layout

Per the locked skill strategy (**author our own**): a Claude Code skill authored for Boundhound, no external references. `.claude/skills/pentest-enum/SKILL.md` orchestrates, all via `bh-exec`, consuming the prior phase's `recon-map.json`:
1. Require an active engagement + an existing `recon-map.json` (the live HTTP services / hosts to enumerate). If absent, tell the operator to run `/recon` first.
2. **ffuf** content discovery on each in-scope live HTTP service: `bh-exec ffuf --target http://<host>/FUZZ -- -w /usr/share/boundhound/wordlists/common.txt -mc 200,204,301,302,307,401,403 -t 40 -o /dev/stdout -of json -s` → `output/enum/ffuf-<host>.json`. Recommend modest threads; note the safety cap. **Fix-wave update:** `-of json` alone never puts JSON on stdout (ffuf's JSON writer only fires when a real `-o` output target is given); `-o /dev/stdout` supplies that target while still landing the bytes on the process's own stdout for the shell redirect to capture. `parseFfufJson` tolerates the bare per-match progress line(s) ffuf still emits on that same stdout ahead of the JSON blob.
3. **nuclei** detection on each in-scope live host: `bh-exec nuclei --target http://<host> -- -jsonl -severity info,low,medium,high,critical -c 25 -rl 150 -disable-update-check` → `output/enum/nuclei-<host>.jsonl`. Document the online-templates vs bundled-template distinction.
4. **bh-enum-map** → `output/enum/enum-map.json`.
Every target still passes scope (bh-exec re-checks). `.claude/commands/enum.md` (`/enum`) loads + follows the skill. Output under `engagements/<name>/output/enum/`.

---

## 6. Safety analysis (enum = the safety layer's real test)

| Capability | Bound |
|---|---|
| Web brute force (ffuf) | scope-checked host; `-t` threads capped (≤500) + `-rate` capped (≤10000) by safety-check; wordlist required |
| Vuln scanning (nuclei) | scope-checked host; `-c` concurrency capped (≤50) + `-rl` rate capped (≤1000); detection-only, intrusive/DoS template categories not orchestrated by the skill |
| Value flags (`-w`,`-t`,`-mc`,…) | fully-anchored `value_pattern`s; loader rejects unanchored; a path/number value can't express a network host (target only via `-u`, scope-checked) |
| Direct Bash bypass | ffuf/nuclei already in `guard.mjs` NETWORK_BINS → denied |

All tools run only inside `docker exec bh-<engagement>`.

**Accepted residual risk — nuclei template content bypasses the `--target` scope check.** `safety-check` and `bh-exec`'s scope re-check both operate on the command line (the `-u`/`--target` value and the declared flags) — nothing inspects the *content* of a `-t` template file, and nuclei templates can hardcode an absolute URL to a host unrelated to `--target` instead of using the `{{BaseURL}}`/`{{Hostname}}` placeholders well-behaved templates use. A template like that would have nuclei itself issue an out-of-scope request that the upstream scope check never sees. The catalog deliberately does not constrain `-t`'s `value_pattern` to a fixed allowlist of template paths, since doing so would defeat nuclei's actual value (detection breadth across its community template set); the accepted mitigation is operational — only run vetted/trusted templates — with a hard mitigation (container network egress-lock, restricting the engagement container's reachable hosts to the in-scope set regardless of template content) deferred to a later phase.

---

## 7. Acceptance criteria

| # | Test | Expect |
|---|---|---|
| E1 | `safety-check` denies nuclei `-c 100` and `-rl 5000`; allows `-c 25`, `-rl 150`; existing caps unchanged | volume bounded |
| E2 | catalog loads with ffuf + nuclei entries; every enum `value_pattern` anchored; `-w`/`-mc` etc. shapes correct; no stray flags | valid + anchored |
| E3 | `enum-map` parsers: ffuf JSON + nuclei JSONL fixtures (incl. blank/malformed lines) → correct normalized object; `by_severity` counts | correct merge |
| E4 | `bh-enum-map` CLI writes `enum-map.json` from a temp `output/enum/`; missing inputs → empty, not crash | correct CLI |
| E5 | Dockerfile static test: ffuf + nuclei pinned installs, COPY of both, wordlist COPY | structure correct |
| E6 | full `bun test` green (regression) | 188+ pass |
| E2E | **REAL:** build image; local nginx target; engagement in-scope; real `bh-exec ffuf` FUZZ finds `index.html` (200) on the target and it lands in `enum-map.json` content[]; real `bh-exec nuclei` with a bundled nginx-detection template produces a finding in `enum-map.json` findings[]; an out-of-scope target DENYs (exit 2 + audit). Offline/deterministic. | real enum + audit |

---

## 8. English hygiene / Deferred
- **Fix-wave update:** the nuclei catalog entry's `-tags` flag (§4 originally listed it) was removed post-review — its `^[a-z0-9,_-]+$` value_pattern let a caller select `dos`/`intrusive`/`fuzz` template categories by name, unenforced by anything else in the safety layer. The skill only ever used `-severity`, never `-tags`, so nothing built on top of this catalog broke.
- Deferred tools (gobuster/feroxbuster/whatweb/dnsx/wpscan/nikto) — later phases.
- Full online nuclei template set — operator-run in real engagements; e2e uses a bundled template for determinism.
- `rate_limit` scope field still parsed-only.
- Renaming `fase-*` filenames + remaining legacy Indonesian docs — tracked English-hygiene follow-up (unchanged).
