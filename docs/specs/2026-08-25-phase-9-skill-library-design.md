# Design Spec — Phase 9: Skill Library Expansion

**Date:** 2026-08-25
**Status:** draft
**Prerequisite:** Phase 0–8 merged.
**Guiding principle:** grow `skills-library/` from a handful of phase-orchestrator skills into a broad library of **self-authored penetration-testing technique playbooks** — one skill per technique (sqli, xss, ssrf, idor, jwt-attacks, subdomain-enum, …), organized by category — so an operator (or the agent) has a written playbook for each common vulnerability class. Breadth like a large public playbook library, but **every skill is written from scratch in our own words and wired to Boundhound's own system** (its bounded tools through `bh-exec`, its phase commands, its scope/safety model). We use a public topic checklist only as a *coverage guide*; we never copy anyone's text. Quality at scale is guaranteed by an **automated validation harness** every skill must pass.

---

## 1. Goal & Non-Goals

### Goal
A validation harness + a large set of technique `SKILL.md` playbooks under `skills-library/<slug>/SKILL.md`, grouped by category, each: self-authored, English, no external references, with valid frontmatter (name = folder, a `Triggers:` line, category/tags), and explicitly tied into Boundhound (references a bounded tool via `bh-exec`, a phase command like `/recon`/`/enum`/`/exploit`/`/verify`/`/report`/`/fullscan`/`/burp`, or the scope/safety model). Plus an index (`skills-library/README.md`) listing the library by category.

### Non-Goals (STRICT)
- ❌ No copied text from any external skill library or project; no external project/tool-suite names, URLs, or attribution anywhere (the actual pentest tool names — subfinder/httpx/nmap/ffuf/nuclei/sqlmap/Burp — are fine as subjects).
- ❌ These are `skills-library/` SOURCE playbooks (breadth), NOT auto-promoted into `.claude/skills/` (the active per-phase skills stay curated). Promotion is a separate, deliberate act.
- ❌ No new attack tool, no catalog/Docker/safety-check/command-builder/bh-exec change. Authoring docs only + one test file + an index.
- ❌ Not aspirational fiction: a skill must describe how the technique is actually approached within Boundhound's bounds — where a technique has no bounded tool yet, it says so and frames the safe path (bring a tool in via `bh-exec` later, or use `/burp` for web), rather than pretending a capability exists.

### Definition of Done
- `test/skill-library.test.mjs`: globs every `skills-library/*/SKILL.md` and validates the invariants (frontmatter shape, `Triggers:`, name==folder, English-only, no external refs, Boundhound wiring, non-trivial body). This is the quality gate.
- A substantial first wave of technique skills across the categories in §3 (target: 100+ skills; the taxonomy supports growing toward ~250 in later waves).
- `skills-library/README.md`: a categorized index of the library.
- All existing tests green; the top-level `README.md` "Structure/Design principles" note updated to reflect the grown library, in this phase's PR.

---

## 2. The validation harness (`test/skill-library.test.mjs`)
For EACH `skills-library/<slug>/SKILL.md` (glob), assert:
- **Frontmatter parses** (YAML block) and has `name`, `description`, `category`, `tags`.
- **name == folder slug** (`<slug>`), lowercase-kebab.
- **`description` contains `Triggers:`** (same convention as the active skills), and is non-empty.
- **English-only:** none of a set of Indonesian sentinel words (reuse the sentinel list style from `test/workflow-skill.test.mjs`).
- **No external references:** none of the forbidden project/vendor sentinels defined in the harness's shared sentinel list (reused byte-identical from `test/workflow-skill.test.mjs`). (Burp/Burp Suite allowed as the subject.)
- **Boundhound wiring:** the body mentions at least one of: `bh-exec`, a bounded tool (`subfinder|httpx|nmap|ffuf|nuclei|sqlmap`), a phase command (`/recon|/enum|/exploit|/verify|/report|/fullscan|/burp`), or `scope.yaml`/scope — so no skill is generic prose detached from our system.
- **Non-trivial body:** more than a minimum length; has at least one `##` section heading.
Plus: an aggregate test that the library has at least N skills (a growth floor), and that every category referenced by a skill appears in the index.

## 3. Category taxonomy (coverage guide — authored ourselves)
- **web-injection:** sqli, blind-sqli, xss-reflected, xss-stored, xss-dom, ssti, command-injection, xxe, ssrf, crlf-injection, nosql-injection, ldap-injection, host-header-injection, http-request-smuggling
- **web-access-control:** idor, broken-access-control, privilege-escalation, path-traversal, lfi, rfi, forced-browsing, insecure-file-upload
- **web-auth-session:** auth-bypass, jwt-attacks, session-fixation, oauth-misconfig, saml-attacks, mfa-bypass, password-reset-poisoning, weak-credential-policy, credential-stuffing
- **web-client:** csrf, cors-misconfig, open-redirect, clickjacking, prototype-pollution, postmessage-abuse, dom-clobbering
- **api:** rest-api-testing, graphql-attacks, mass-assignment, bola-idor-api, bfla, api-key-leakage, swagger-openapi-recon, api-rate-limit-testing
- **recon-osint:** subdomain-enumeration, dns-recon, certificate-transparency, google-dorking, github-recon, cloud-asset-discovery, tech-fingerprinting, wayback-recon, vhost-discovery, port-service-scanning
- **infra-network:** smb-enumeration, snmp-enumeration, ftp-anonymous, ssl-tls-audit, default-credentials, service-version-audit, network-segmentation-check
- **info-disclosure:** sensitive-data-exposure, verbose-error-messages, backup-file-discovery, exposed-git, source-map-exposure, debug-endpoint-exposure, directory-listing
- **business-logic:** race-condition, workflow-bypass, price-parameter-tampering, insufficient-quantity-validation
- **methodology:** bug-bounty-workflow, recon-methodology, scope-analysis, severity-triage, report-writeup, retest-verification

(~90–110 slugs above; later waves can extend each category toward the ~250 target.)

## 4. Per-skill shape (authored in our words)
Each `SKILL.md`:
- Frontmatter: `name` (==slug), `description` (one paragraph ending with a `Triggers:` list), `version: 1.0.0`, `phase` (the closest Boundhound phase array, e.g. `["exploit"]`), `category` (array), `tags` (array).
- Body sections (our words): **What it is** (the vuln/technique, briefly), **Where it shows up** (typical signals), **How Boundhound approaches it** (which bounded tool via `bh-exec` / which phase command / or `/burp`; if no bounded tool yet, say so and give the safe path), **Scope & safety** (stays in `scope.yaml`, deny-by-default, non-destructive proof-of-vuln), **Remediation** (short). Truthful, concise, no copied text.

## 5. Safety analysis
| Concern | Bound |
|---|---|
| New content only | authoring `skills-library/` docs + one test + an index; NO code/tool/catalog/Docker/safety change |
| No capability inflation | skills describe techniques within Boundhound's existing bounds; where no bounded tool exists, they say so — they do not grant or imply new attack capability |
| Originality/no attribution | harness forbids external-project references; all text self-authored |
No new attack surface: a playbook is documentation; the enforcement layer is unchanged.

## 6. Acceptance criteria
| # | Test | Expect |
|---|---|---|
| L1 | harness: every `skills-library/*/SKILL.md` passes frontmatter/name==folder/Triggers/English/no-external-ref/wiring/non-trivial | all skills valid |
| L2 | harness: library has ≥ the growth floor of skills; every skill's category is in the index | breadth + indexed |
| L3 | spot-check: a sampling of skills are genuinely self-authored, wired to Boundhound, truthful (not fiction) | quality |
| L4 | full `bun test` green | 690+ pass |

---

## 7. Deferred / notes
- Later waves extend each category toward ~250 skills; the harness makes each wave safe to add.
- Optional future: a promoter that turns a chosen library skill into an active `.claude/skills/` skill.
- Tracked pre-existing follow-ups remain (fase-* filename cleanup, CI workflow, etc.).
