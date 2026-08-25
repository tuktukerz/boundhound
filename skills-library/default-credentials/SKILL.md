---
name: default-credentials
description: "Default-credential checking is testing whether a service is still running with a documented, out-of-the-box vendor username/password pair that was never changed after installation -- a small, targeted check against a short, publicly documented list of factory defaults for the specific product identified, not a brute-force or credential-guessing exercise. Use this skill once a service's product and version have already been identified, to check the narrow, well-known set of defaults that ship with that exact product. Triggers: 'default credentials', 'default password check', 'factory default login', 'admin admin login', 'unchanged vendor password'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["infra-network"]
tags: ["default-credentials", "misconfiguration", "authentication", "network"]
---

# Default Credentials

## What it is
Many devices and software packages ship from the vendor with a preset login -- a known administrator username and password meant to be changed on first use. Default-credential checking is testing whether that change was ever made, for the exact product and version already identified on the target, against the small number of defaults that vendor is publicly documented to ship. It is not a password-guessing attack; it is confirming or ruling out a single, well-known configuration gap.

## Where it shows up
Network appliances, admin panels for identified software, and database or management consoles surfaced during service and version identification are where this recurs most: infrastructure that is set up once, works, and is never revisited for a setting that does not look like a security control to whoever installed it.

## How Boundhound approaches it
Once nmap and, where applicable, httpx identify a service's vendor, product, and version during `/recon` (through `bh-exec`), a default-credential check is limited to the short, fixed list of factory pairs documented for that exact identified product -- never a general wordlist-driven guessing sweep. Boundhound has no dedicated bounded tool that automates this today; running it is a manual, operator-directed step limited to that documented set, or a task for a future dedicated tool brought into the system through `bh-exec` under the same scope and safety review every bounded tool receives. Regardless of how it is performed, Boundhound's safety layer caps request rates and denies anything resembling a flood or denial-of-service pattern, so even a manual check stays to a handful of attempts against a single identified service, never an extended guessing session.

## Scope & safety
Only an already-identified, in-scope service gets any credential check at all, and the check is limited strictly to the documented default(s) for that exact product and version -- never a general username/password list, and never repeated attempts beyond the small documented set. The safety layer's rate limits and denial of flood-like patterns apply regardless of how the check is executed, and any sign of an account-lockout risk is a reason to stop the check, not push through it.

## Remediation
Change every default credential as a mandatory step of deployment, before a service goes live on any reachable network, and enforce that as part of a standard rollout process rather than leaving it to an individual administrator's memory. Require a minimum credential complexity on first login and monitor for repeated failed logins against known default usernames.
