# Skills Library

Boundhound's self-authored penetration-testing **technique-playbook library** — one
playbook per technique (SQL injection, cross-site scripting, SSRF, IDOR, JWT
attacks, subdomain enumeration, and so on), grouped by category. This is
**source breadth**, not the active skill set: nothing here is auto-promoted
into `.claude/skills/`. Turning a library playbook into an active skill is a
separate, deliberate step, not automatic.

Every skill in this library is:

- self-authored, in our own words — no copied text from any external skill
  library or project
- English-only
- free of external project/vendor references (the pentest tools themselves —
  subfinder, httpx, nmap, ffuf, nuclei, sqlmap, Burp — are fine as subjects,
  since Boundhound actually runs some of them through `bh-exec`)
- explicitly wired to Boundhound's own system: a bounded tool via `bh-exec`,
  a phase command (`/recon`, `/enum`, `/exploit`, `/verify`, `/report`,
  `/fullscan`, `/burp`), or the scope/safety model
- validated by `test/skill-library.test.mjs`, which globs every
  `skills-library/*/SKILL.md` and enforces these invariants — the harness is
  the quality gate for every batch added to this library

Where a technique has no bounded tool yet, its playbook says so plainly and
describes the safe path (bring a tool in through `bh-exec` later, or use
`/burp` for web work) instead of pretending a capability exists.

## Categories

Skills are grouped into the following categories. Each category below will
be filled in with its skills as later batches land; a category appears here
even before it has any skills yet, so the index stays complete as the
library grows.

### web-injection
Injection-class web vulnerabilities: sqli, blind-sqli, xss-reflected,
xss-stored, xss-dom, ssti, command-injection, xxe, ssrf, crlf-injection,
nosql-injection, ldap-injection, host-header-injection,
http-request-smuggling.

_No skills authored yet — pending a later batch._

### web-access-control
Access-control failures on the web: idor, broken-access-control,
privilege-escalation, path-traversal, lfi, rfi, forced-browsing,
insecure-file-upload.

_No skills authored yet — pending a later batch._

### web-auth-session
Authentication and session-handling weaknesses: auth-bypass, jwt-attacks,
session-fixation, oauth-misconfig, saml-attacks, mfa-bypass,
password-reset-poisoning, weak-credential-policy, credential-stuffing.

_No skills authored yet — pending a later batch._

### web-client
Client-side web weaknesses: csrf, cors-misconfig, open-redirect,
clickjacking, prototype-pollution, postmessage-abuse, dom-clobbering.

_No skills authored yet — pending a later batch._

### api
API-specific technique playbooks: rest-api-testing, graphql-attacks,
mass-assignment, bola-idor-api, bfla, api-key-leakage,
swagger-openapi-recon, api-rate-limit-testing.

_No skills authored yet — pending a later batch._

### recon-osint
Reconnaissance and open-source intelligence gathering: subdomain-enumeration,
dns-recon, certificate-transparency, google-dorking, github-recon,
cloud-asset-discovery, tech-fingerprinting, wayback-recon, vhost-discovery,
port-service-scanning.

_No skills authored yet — pending a later batch._

### infra-network
Infrastructure and network-service technique playbooks: smb-enumeration,
snmp-enumeration, ftp-anonymous, ssl-tls-audit, default-credentials,
service-version-audit, network-segmentation-check.

_No skills authored yet — pending a later batch._

### info-disclosure
Information-disclosure technique playbooks: sensitive-data-exposure,
verbose-error-messages, backup-file-discovery, exposed-git,
source-map-exposure, debug-endpoint-exposure, directory-listing.

_No skills authored yet — pending a later batch._

### business-logic
Business-logic technique playbooks: race-condition, workflow-bypass,
price-parameter-tampering, insufficient-quantity-validation.

_No skills authored yet — pending a later batch._

### methodology
Engagement-methodology playbooks: bug-bounty-workflow, recon-methodology,
scope-analysis, severity-triage, report-writeup, retest-verification.

_No skills authored yet — pending a later batch._

## Existing entries

- `pentest-mode` — the engagement-mode selector skill that pre-dates this
  library; kept here as the reference for the existing `SKILL.md` shape
  (frontmatter with `name`/`description`/`category`/`tags` and a `Triggers:`
  line in the description). It is not part of the category taxonomy above.
