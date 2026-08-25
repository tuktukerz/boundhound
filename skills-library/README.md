# Boundhound Skill Library

A library of **self-authored penetration-testing technique playbooks** — one skill per technique, organized by category. Each `SKILL.md` is written from scratch in our own words and wired to Boundhound's own system: its bounded tools through the `bh-exec` choke point, its phase commands (`/recon`, `/enum`, `/exploit`, `/verify`, `/report`, `/fullscan`, `/burp`), and its deny-by-default scope model.

These are **source playbooks** — reference material and a coverage map for the techniques Boundhound reasons about. They are not auto-loaded as active skills; the curated per-phase skills under `.claude/skills/` are promoted deliberately, one phase at a time. A playbook is honest about Boundhound's real bounds: where a technique has a bounded tool it names it; where one does not exist yet, it says so and describes the safe, in-scope path rather than implying a capability that isn't there.

Every skill is validated by `test/skill-library.test.mjs` (valid frontmatter, `Triggers:` line, English-only, no external-project references, real Boundhound wiring, non-trivial body).

**81 skills across 11 categories.**

---

## web-injection (14)
Injection flaws where untrusted input is interpreted as code/query/markup.

`sqli` · `blind-sqli` · `xss-reflected` · `xss-stored` · `xss-dom` · `ssti` · `command-injection` · `xxe` · `ssrf` · `crlf-injection` · `nosql-injection` · `ldap-injection` · `host-header-injection` · `http-request-smuggling`

## web-access-control (8)
Authorization and object/function access failures.

`idor` · `broken-access-control` · `privilege-escalation` · `path-traversal` · `lfi` · `rfi` · `forced-browsing` · `insecure-file-upload`

## web-auth-session (9)
Authentication and session-management weaknesses.

`auth-bypass` · `jwt-attacks` · `session-fixation` · `oauth-misconfig` · `saml-attacks` · `mfa-bypass` · `password-reset-poisoning` · `weak-credential-policy` · `credential-stuffing`

## web-client (7)
Client-side and browser-trust flaws.

`csrf` · `cors-misconfig` · `open-redirect` · `clickjacking` · `prototype-pollution` · `postmessage-abuse` · `dom-clobbering`

## api (8)
REST/GraphQL API-specific testing.

`rest-api-testing` · `graphql-attacks` · `mass-assignment` · `bola-idor-api` · `bfla` · `api-key-leakage` · `swagger-openapi-recon` · `api-rate-limit-testing`

## recon-osint (10)
Attack-surface discovery and passive intelligence.

`subdomain-enumeration` · `dns-recon` · `certificate-transparency` · `google-dorking` · `github-recon` · `cloud-asset-discovery` · `tech-fingerprinting` · `wayback-recon` · `vhost-discovery` · `port-service-scanning`

## infra-network (7)
Service and infrastructure exposure.

`smb-enumeration` · `snmp-enumeration` · `ftp-anonymous` · `ssl-tls-audit` · `default-credentials` · `service-version-audit` · `network-segmentation-check`

## info-disclosure (7)
Exposed data, files, and configuration.

`sensitive-data-exposure` · `verbose-error-messages` · `backup-file-discovery` · `exposed-git` · `source-map-exposure` · `debug-endpoint-exposure` · `directory-listing`

## business-logic (4)
Flaws in intended application workflow.

`race-condition` · `workflow-bypass` · `price-parameter-tampering` · `insufficient-quantity-validation`

## methodology (6)
Process playbooks tying Boundhound's pipeline together.

`bug-bounty-workflow` · `recon-methodology` · `scope-analysis` · `severity-triage` · `report-writeup` · `retest-verification`

## recon (1)
`pentest-mode` — engagement mode selector.
