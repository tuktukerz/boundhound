# Phase 9 — Skill Library Expansion: Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Grow `skills-library/` into a broad, self-authored technique-playbook library (target 100+ skills this wave), each wired to Boundhound and passing an automated validation harness. Authoring docs only; no code/tool/catalog/Docker/safety change.

**Spec:** `docs/specs/2026-08-25-phase-9-skill-library-design.md`

## Global Constraints
- NO change to `tools-catalog.json`, `docker/Dockerfile`, `src/safety/safety-check.mjs`, `src/command-builder/command-builder.mjs`, `bin/bh-exec.mjs`, or any `src/`/`bin/`/`hooks/` code. Phase 9 touches only `skills-library/`, `test/skill-library.test.mjs`, `docs/`, and `README.md`.
- Every skill: self-authored (our words, NO copied text), English only, NO external project/vendor references (Burp/tool names OK as subjects), valid frontmatter with a `Triggers:` line, `name` == folder slug, and explicit Boundhound wiring (bh-exec / a bounded tool / a phase command / scope). Must pass `test/skill-library.test.mjs`.
- Node ESM `.mjs`, `bun test`, no build step. Batch same-shape authoring (one subagent per category); the harness is the quality gate.

---

### Task 1: validation harness + library index scaffold

**Files:** Create `test/skill-library.test.mjs`, `skills-library/README.md` (index scaffold with the category list).

**Interfaces produced (spec §2):** the harness globs `skills-library/*/SKILL.md` and validates each (frontmatter parses + has name/description/category/tags; name==folder; description has `Triggers:`; English-only sentinels; no external-ref sentinels; Boundhound wiring; non-trivial body with a `##`); plus a growth-floor count and category-in-index checks. The index lists categories → skills.

- [ ] Read `test/workflow-skill.test.mjs` (sentinel-array style, frontmatter parsing) + `skills-library/pentest-mode/SKILL.md` (existing format) first.
- [ ] Write the harness. Since only `pentest-mode` exists now, set the growth-floor to pass with the current count but assert per-skill invariants on whatever exists (so it stays green through the batches and tightens as skills land). Ensure `pentest-mode` passes (adjust the harness to its real frontmatter, not the reverse — don't edit pentest-mode's content beyond what's needed to satisfy a reasonable invariant).
- [ ] Run → GREEN on the current library. FULL `bun test`.
- [ ] Commit: `test(skills): skill-library validation harness + index scaffold`

---

### Tasks 2–11: category authoring batches (one per category)

For EACH category below, dispatch ONE subagent that authors every skill in that category as `skills-library/<slug>/SKILL.md`, all passing the Task-1 harness. The subagent gets: the spec's per-skill shape (§4), the category's slug list, the wiring guidance (map each technique to the closest Boundhound bounded tool / phase command / `/burp`, and where none exists say so + give the safe path), and the hard rules (self-authored, English, no external refs). After each batch: run the harness + a controller spot-check of 2–3 skills for genuine quality (self-authored, wired, truthful), then commit.

- [ ] **T2 web-injection** (sqli, blind-sqli, xss-reflected, xss-stored, xss-dom, ssti, command-injection, xxe, ssrf, crlf-injection, nosql-injection, ldap-injection, host-header-injection, http-request-smuggling) → commit `feat(skills): web-injection technique library`
- [ ] **T3 web-access-control** (idor, broken-access-control, privilege-escalation, path-traversal, lfi, rfi, forced-browsing, insecure-file-upload) → commit `feat(skills): web-access-control technique library`
- [ ] **T4 web-auth-session** (auth-bypass, jwt-attacks, session-fixation, oauth-misconfig, saml-attacks, mfa-bypass, password-reset-poisoning, weak-credential-policy, credential-stuffing) → commit `feat(skills): web-auth-session technique library`
- [ ] **T5 web-client** (csrf, cors-misconfig, open-redirect, clickjacking, prototype-pollution, postmessage-abuse, dom-clobbering) → commit `feat(skills): web-client technique library`
- [ ] **T6 api** (rest-api-testing, graphql-attacks, mass-assignment, bola-idor-api, bfla, api-key-leakage, swagger-openapi-recon, api-rate-limit-testing) → commit `feat(skills): api technique library`
- [ ] **T7 recon-osint** (subdomain-enumeration, dns-recon, certificate-transparency, google-dorking, github-recon, cloud-asset-discovery, tech-fingerprinting, wayback-recon, vhost-discovery, port-service-scanning) → commit `feat(skills): recon-osint technique library`
- [ ] **T8 infra-network** (smb-enumeration, snmp-enumeration, ftp-anonymous, ssl-tls-audit, default-credentials, service-version-audit, network-segmentation-check) → commit `feat(skills): infra-network technique library`
- [ ] **T9 info-disclosure** (sensitive-data-exposure, verbose-error-messages, backup-file-discovery, exposed-git, source-map-exposure, debug-endpoint-exposure, directory-listing) → commit `feat(skills): info-disclosure technique library`
- [ ] **T10 business-logic** (race-condition, workflow-bypass, price-parameter-tampering, insufficient-quantity-validation) → commit `feat(skills): business-logic technique library`
- [ ] **T11 methodology** (bug-bounty-workflow, recon-methodology, scope-analysis, severity-triage, report-writeup, retest-verification) → commit `feat(skills): methodology technique library`

(Batches are independent — a failed/flaky batch can be re-dispatched without affecting the others. The harness gates every batch.)

---

### Task 12: index finalize + README

**Files:** Modify `skills-library/README.md` (full categorized index of all authored skills), `README.md` (top-level: note the grown skill library in Structure/Design-principles; update `bun test` count).

- [ ] Fill `skills-library/README.md` with every category → its skills. Update top-level README: Structure note that `skills-library/` is now a broad technique-playbook library (N skills across M categories), self-authored + wired to Boundhound; update `bun test` count. No external refs, no "Fase".
- [ ] FULL `bun test`.
- [ ] Commit: `docs(skills): finalize skill-library index + README`

---

## Self-Review
- Spec coverage: §2→T1, §3/§4→T2–T11, index+README→T12. ✅
- Authoring only (no code/tool/catalog/Docker/safety change); harness gates quality at scale; every skill self-authored + English + no external refs + Boundhound-wired; batches independent + retryable.
