---
name: subdomain-enumeration
description: "Subdomain enumeration is discovering the hostnames a target organization actually owns and exposes -- www, api, staging, admin, and forgotten or unofficial subdomains -- by combining passive data sources with active DNS resolution, since an organization's real attack surface is almost always larger than the handful of domains anyone remembers publishing. Use this skill when an engagement's scope is defined by a root domain (or a small set of them) and the real attack surface -- everything actually running under that domain -- still needs to be mapped before any other testing starts. Triggers: 'subdomain enumeration', 'subdomain discovery', 'find subdomains', 'subfinder', 'attack surface mapping'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["subdomain", "enumeration", "subfinder", "httpx", "recon"]
---

# Subdomain Enumeration

## What it is
Subdomain enumeration is the process of finding every hostname that resolves under a target's root domain(s), not just the ones a company's marketing site or public docs choose to mention. An organization's real exposure lives across `api.`, `staging.`, `admin.`, `dev.`, and one-off subdomains spun up for a forgotten project years ago that no one remembers to decommission. Because active scanning can only test what it can name, subdomain enumeration is the multiplier at the start of an engagement: every subdomain found is a candidate host for every later phase.

## Where it shows up
Passive sources -- certificate transparency logs, historical DNS records, and public datasets that reference a domain without ever sending it a request -- surface names an attacker never has to touch the target to learn. Active DNS resolution then confirms which of those names actually point somewhere today, since passive sources are full of stale and decommissioned entries. Forgotten staging environments, internal tools accidentally left with public DNS records, and third-party services still pointing at an old subdomain are the recurring high-value finds.

## How Boundhound approaches it
During `/recon`, Boundhound runs subfinder (through `bh-exec`) against every root domain in `scope.yaml` to pull subdomain names from its passive source set, without sending a single packet to the target itself. Every name subfinder returns is then handed to httpx (also through `bh-exec`) to resolve and probe which ones are actually live -- this collapses a long passive list into a short, confirmed set of reachable hosts before any heavier tool ever runs against them.

## Scope & safety
subfinder only queries third-party passive sources, so it carries essentially no risk to the target; httpx's resolution and probing step is deliberately lightweight (a handful of requests per host) and still governed by `scope.yaml` deny-by-default like every other `bh-exec` invocation. A subdomain surfaced by subfinder is a candidate, not automatically in scope -- it is only carried into `/enum` or `/exploit` once it has been confirmed live and belongs to the engagement's approved root domain.

## Remediation
Maintain an accurate inventory of DNS records and retire the ones pointing at decommissioned infrastructure; a subdomain with no owner is a liability whether or not it currently resolves. Treat every newly discovered subdomain as part of the production attack surface until proven otherwise, and apply the same authentication and hardening standards to staging or internal-sounding hostnames as to the main site.
