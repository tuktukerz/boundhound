---
name: dns-recon
description: "DNS recon is querying a target's DNS records directly -- A/AAAA, MX, TXT, NS, SOA, and attempting zone transfers -- to learn mail infrastructure, third-party service integrations (via SPF/TXT records), authoritative name servers, and misconfigurations like a name server that still permits a full zone transfer to anyone who asks. Use this skill when a target's DNS configuration itself, rather than just the subdomains it publishes, needs to be understood -- mail routing, SPF/DKIM/DMARC posture, or a name server that might be misconfigured. Triggers: 'dns recon', 'dns enumeration', 'zone transfer', 'dns records', 'mx record lookup'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["dns", "recon", "zone-transfer", "osint"]
---

# DNS Recon

## What it is
DNS recon reads the DNS records a target's name servers publish -- not just the hostnames under a domain, but what those records say about the organization: which providers handle its mail (MX), what services are authorized to send mail on its behalf (SPF in TXT records), which name servers are authoritative (NS), and, occasionally, whether a name server will still hand a complete zone transfer (AXFR) to anyone who asks. A permissive zone transfer is the standout misconfiguration here: it can leak an organization's entire internal DNS structure, including hosts never meant to be public, in a single query.

## Where it shows up
SOA and NS records reveal which name servers are authoritative and worth testing for a misconfigured zone transfer. TXT records carry SPF/DMARC entries that name every third-party mail and marketing service an organization has ever authorized -- a useful map of its vendor relationships. MX records show where mail actually routes, which matters for confirming a domain is genuinely in active use rather than parked.

## How Boundhound approaches it
Boundhound has no dedicated bounded tool that performs full DNS record enumeration or zone-transfer attempts today -- this playbook is passive OSINT, not something `/recon` auto-runs end to end. What Boundhound does run through `bh-exec` is subfinder, whose passive sources return hostnames derived in part from DNS-adjacent data, and httpx, which resolves each candidate host as part of confirming it is live. Deeper DNS record inspection (MX/TXT/SOA/zone transfer) is manual analyst work today; any hostname or mail-related finding it turns up must be added to `scope.yaml` and cleared before it feeds into `/recon`'s httpx probing (through `bh-exec`) or any further active tool run.

## Scope & safety
A DNS query against a public name server is minimally invasive, but the hostnames and infrastructure a DNS recon pass surfaces are not automatically in scope -- each one is added to `scope.yaml` and confirmed before any active tool touches it. A permissive zone transfer, if found, is documented as a finding, not used as a shortcut to start scanning newly-revealed hosts before scope is updated.

## Remediation
Disable zone transfers to anyone other than an organization's own secondary name servers, and audit TXT/SPF records periodically to remove authorizations for services no longer in use. Keep DNS records for decommissioned infrastructure cleaned up rather than left resolving indefinitely.
