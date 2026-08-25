---
name: recon-methodology
description: "How Boundhound drives reconnaissance: passive subdomain discovery with subfinder, HTTP probing of every live candidate with httpx, and port/service scanning with nmap against confirmed live hosts, all normalized by bh-recon-map into recon-map.json for /enum to consume. Use this skill when starting recon on a new engagement, deciding what order to run recon tools in, or explaining why a host was or was not scanned. Triggers: 'recon methodology', 'subdomain discovery', 'recon chain', 'recon-map', 'passive recon', 'attack surface mapping'."
version: 1.0.0
phase: ["recon"]
category: ["methodology"]
tags: ["recon", "methodology", "subfinder", "httpx", "nmap", "recon-map"]
---

# Recon Methodology

## What it is
Reconnaissance is the first phase of an engagement: turning a small set of in-scope domains into a concrete list of live hosts, exposed HTTP services, and open ports that later phases can act on. Good recon methodology is ordered -- each tool narrows the candidate set for the next one -- rather than firing every tool at every possible target simultaneously, which wastes requests against hosts that were never going to be reachable or in scope.

## How Boundhound approaches it
`/recon` runs a fixed three-tool chain, each step through `bh-exec`: subfinder performs passive subdomain discovery against the in-scope root domain(s), producing candidate subdomains without touching the target directly. Every candidate that clears the `in_scope` wildcard rule (plus the root domain itself) is then probed with httpx, which confirms which hosts actually respond over HTTP(S) and records status, title, and technology signals. Only hosts httpx confirms live move on to nmap, which scans them for open ports and service banners. Running the chain in this order -- passive first, then a lightweight probe, then the heavier scan -- means nmap never spends time against a host that recon already knows is unreachable or not serving HTTP.

## Feeding the result forward
Once all three tools finish, `bh-recon-map` normalizes their raw output into a single `recon-map.json`: a list of hosts, each with its resolved ports and any HTTP service detected. `/enum` reads this file's `http_services` directly rather than re-discovering hosts itself, and re-screens every host against the engagement's current in-scope/out-of-scope lists before probing further -- so a host recon considered in-scope is checked again, since scope can be tightened between phases. A malformed or missing `recon-map.json` stops `/enum` before it starts rather than letting it invent targets.

## Scope & safety
Every candidate subdomain and host is checked against `scope.yaml`'s in-scope domains and wildcard rules before subfinder, httpx, or nmap ever runs against it -- deny-by-default, so nothing outside the program's boundaries gets probed even indirectly through passive discovery. All three tools run only through `bh-exec`, which additionally enforces the engagement's rate limit and logs every invocation for the audit trail.

## Checklist
- Confirm `/engagement` has already populated `in_scope.domains` -- `/recon` refuses to run against an empty scope.
- Let subfinder run first and complete before httpx probes candidates; do not skip straight to nmap against guessed hosts.
- Only scan ports on hosts httpx already confirmed live.
- Review `recon-map.json`'s host list before moving to `/enum` -- a suspiciously large or suspiciously small result is worth a second look before continuing the chain.
