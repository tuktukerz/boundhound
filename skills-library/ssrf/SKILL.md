---
name: ssrf
description: "Server-side request forgery occurs when an application makes an outbound HTTP (or other protocol) request based on user-supplied input -- a URL, hostname, or IP -- letting an attacker redirect that request to internal-only services, cloud metadata endpoints, or other hosts the server can reach but the attacker cannot reach directly. Use this skill when a feature fetches a URL on the user's behalf: webhooks, an 'import from URL' feature, PDF/screenshot generation, image proxies, or URL-preview features. Triggers: 'ssrf', 'server-side request forgery', 'internal network pivot', 'metadata endpoint access', 'url fetch injection'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["ssrf", "internal-network", "web", "injection"]
---

# Server-Side Request Forgery

## What it is
SSRF turns the server's own network position into an attack surface: instead of the attacker fetching a URL directly, the server fetches it on their behalf, from wherever the server happens to sit on the network. That server-side vantage point can reach internal services, admin interfaces, or cloud-provider metadata endpoints that are normally unreachable from the outside.

## Where it shows up
Any feature that takes a URL, hostname, or callback address as input and has the server fetch it: webhook configuration, "import a document/image from URL," server-side PDF or screenshot rendering, URL unfurling/preview, and image-proxy features are the classic entry points. A response time or content difference when the supplied URL points at an internal IP range versus a public one is a strong signal.

## How Boundhound approaches it
`/enum` runs nuclei (through `bh-exec`) against discovered endpoints, and its template set includes a number of SSRF detection checks (including out-of-band-callback-style templates) that can catch a matching case. Boundhound does not currently have a bounded tool that actively pivots through a confirmed SSRF into internal network reconnaissance -- that capability doesn't exist yet. Where a candidate is flagged or suspected, the safe path is manual verification through `/burp`: point the vulnerable parameter at a controlled, already-in-scope target (never at an arbitrary internal address or a cloud metadata endpoint) via Repeater, and confirm the server-side fetch occurred. A dedicated bounded SSRF-exploitation tool can be brought in through `bh-exec` in a future phase.

## Scope & safety
Verification probes point only at hosts already covered by `scope.yaml` -- Boundhound does not use SSRF findings to probe arbitrary internal infrastructure or cloud metadata endpoints that are outside scope, even if the finding suggests they'd be reachable. The proof is that the server made the fetch, not what could be reached beyond scope.

## Remediation
Validate and allow-list destination hosts/IPs for any server-side fetch, resolving DNS server-side and re-checking the resolved IP against the allow-list to prevent DNS-rebinding bypasses. Block requests to link-local, loopback, and cloud metadata address ranges by default at the network layer as well as in application logic.
