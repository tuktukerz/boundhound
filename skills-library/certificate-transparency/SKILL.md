---
name: certificate-transparency
description: "Certificate transparency (CT) recon is mining the public, append-only CT logs that browsers require every publicly-trusted TLS certificate to be recorded in, to find every hostname an organization has ever requested a certificate for -- including subdomains never linked anywhere and never intended to be public. Use this skill when a target's certificate history might reveal hosts that plain web crawling or DNS brute-forcing would never surface. Triggers: 'certificate transparency', 'ct log search', 'ssl certificate recon', 'subdomain via certificates', 'ct-based subdomain discovery'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["certificate-transparency", "ct-logs", "tls", "subfinder", "osint"]
---

# Certificate Transparency Recon

## What it is
Every publicly-trusted TLS certificate issued today is recorded in a public, append-only Certificate Transparency log as a condition of being trusted by major browsers. Because a certificate lists every hostname it covers -- including wildcard and multi-domain (SAN) certificates -- searching CT logs surfaces subdomains an organization requested a certificate for at some point, whether or not that host was ever linked from a website, indexed by a search engine, or intentionally made public. It is one of the highest-signal passive sources available precisely because it comes from the target's own certificate requests, not a guess.

## Where it shows up
Wildcard certificates and multi-domain SAN certificates are the richest finds -- a single certificate can reveal dozens of hostnames at once, including internal-sounding or staging names an organization never meant to expose. A certificate issued for a short-lived project or an old rebrand often still sits in CT log history long after the host itself was decommissioned, which is exactly why every name found this way still needs live confirmation before it is trusted.

## How Boundhound approaches it
Boundhound has no separate, dedicated tool that queries CT logs on its own -- certificate transparency is one of several passive sources that subfinder draws from internally when it runs during `/recon` (through `bh-exec`). In practice this means running subfinder against a scoped root domain already pulls in CT-log-derived hostnames alongside its other passive sources, with no extra step required. Every name subfinder returns, from CT logs or otherwise, is then resolved and probed with httpx (also through `bh-exec`) to determine which ones are actually live before anything further happens to them.

## Scope & safety
Querying public CT log data touches only third-party infrastructure, never the target, so it carries no risk of alerting or affecting anything in scope. A hostname surfaced through certificate transparency is a candidate only -- it is added to `scope.yaml` and confirmed live via httpx before it is carried into `/enum` or any active tool.

## Remediation
Avoid using descriptive, internal-sounding hostnames in certificates for infrastructure that should stay private -- CT logs make that naming permanently public and searchable. Decommission certificates, and the hosts behind them, promptly rather than leaving a forgotten subdomain resolving to live infrastructure years after a project ended.
