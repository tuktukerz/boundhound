---
name: github-recon
description: "GitHub recon is searching public code-hosting platforms for a target's own repositories, commit history, and code search results to find secrets, internal hostnames, and configuration details that were committed -- even briefly -- and never fully scrubbed once removed. Use this skill when an organization's development activity is visible on a public code-hosting platform, since a single committed secret or internal reference can outlive the commit that 'removed' it. Triggers: 'github recon', 'repository recon', 'leaked secrets in code', 'commit history search', 'public repo osint'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["github", "code-search", "osint", "secrets", "passive-recon"]
---

# GitHub Recon

## What it is
Public code-hosting platforms let anyone search an organization's public repositories, commit history, and code content directly. A secret committed even once -- an API key, a database connection string, an internal hostname -- can remain retrievable through commit history long after a later commit "removes" it, because removing a file from the current tree does not erase it from history. GitHub recon is the practice of searching that surface deliberately: repositories belonging to the organization or its employees, code search for known secret patterns, and commit history for anything that was fixed rather than rotated.

## Where it shows up
Organization and employee-owned repositories sometimes include internal tooling, infrastructure-as-code, or CI/CD configuration that references internal hostnames, service names, or credentials meant to stay private. Commit history is the recurring trap: a developer commits a secret, notices, and deletes it in a later commit -- but the original commit is still reachable, and the secret is still live unless it was also rotated. Forked or abandoned repositories from former employees or old projects are frequently forgotten entirely.

## How Boundhound approaches it
Boundhound has no bounded tool that searches a code-hosting platform's repositories or commit history -- this playbook is manual, analyst-driven passive OSINT, not something `/recon` automates end to end. Nothing here sends a request to the target; every search is against the public code-hosting platform's own index. Any secret, hostname, or configuration detail this turns up feeds directly into scope decisions: a newly discovered internal host is added to `scope.yaml` and confirmed before `/recon`'s httpx probing (through `bh-exec`) or any active tool touches it, and a discovered credential is handled per this library's api-key-leakage playbook rather than tested here.

## Scope & safety
Every query in this playbook targets the code-hosting platform's own public index, never the organization being assessed, so it carries no risk of alerting or affecting anything in scope. A repository or hostname found this way is a lead, not an automatic target -- it is only carried into active testing once it is confirmed to belong to the engagement and added to `scope.yaml`.

## Remediation
Rotate any secret that was ever committed to version control, even briefly and even if later removed -- history retains it regardless of what the current tree shows. Use pre-commit secret scanning and a documented process for handling employee-owned or forked repositories that reference organizational infrastructure.
