---
name: vhost-discovery
description: "Virtual host (vhost) discovery is finding additional sites or applications hosted behind the same IP address but reachable only under a specific Host header -- internal, staging, or unlisted virtual hosts that never appear in DNS or a certificate because they were never meant to be reached from outside a Host-header-aware router. Use this skill against any confirmed live IP where the discovered subdomains might not represent everything actually served from that address. Triggers: 'vhost discovery', 'virtual host enumeration', 'host header fuzzing', 'hidden vhost', 'unlisted virtual host'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["recon-osint"]
tags: ["vhost", "host-header", "ffuf", "httpx", "enumeration"]
---

# Vhost Discovery

## What it is
Many servers host multiple sites or applications behind a single IP address, routing each request to the correct one based on the `Host` header rather than the IP itself. Virtual host discovery finds the ones that were never meant to be reached externally -- an internal admin panel, a staging deployment, or a legacy application -- by sending requests to a known IP with a range of candidate Host headers and watching for a response that differs from the default site. Because these vhosts often have no DNS record and no certificate SAN entry pointing at them, subdomain enumeration and certificate transparency can both miss them entirely; they only reveal themselves to a request that already knows (or guesses) the right header.

## Where it shows up
Shared hosting and internal load balancers are the classic case -- a public-facing IP that also happens to route an internal tool or staging environment for anyone who sends the right Host header. A differing response length, status code, redirect target, or page title against an otherwise identical IP and port is the signal that a candidate Host header hit something real instead of the default catch-all site.

## How Boundhound approaches it
During `/enum`, Boundhound runs ffuf (through `bh-exec`) to fuzz the Host header against a confirmed live IP with a wordlist of candidate vhost names, comparing each response against the baseline default-site response to flag genuine differences. Any vhost name that surfaces this way is then probed with httpx (through `bh-exec`) during `/recon` the same as any other discovered host, to confirm it is live and fingerprint what it runs before it moves any further.

## Scope & safety
A confirmed vhost is a new host reachable at an already-in-scope IP, but a new hostname is not automatically covered by the same scope entry -- it is added to `scope.yaml` explicitly before being carried into `/enum` or `/exploit`. ffuf's Host-header fuzzing runs only against IPs already confirmed in scope through `bh-exec`'s deny-by-default enforcement, and the wordlist-driven requests are ordinary GETs, not an attempt to exploit whatever vhost is found.

## Remediation
Restrict internal or staging vhosts to internal networks or an authenticated reverse proxy rather than relying on an unadvertised Host header as the only barrier -- Host-header fuzzing is trivial and fast. Configure a sane default site for unmatched Host headers so an unlisted vhost does not accidentally confirm its own existence.
