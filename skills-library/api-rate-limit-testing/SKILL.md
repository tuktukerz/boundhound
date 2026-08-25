---
name: api-rate-limit-testing
description: "API rate-limit testing checks whether an endpoint enforces a request-rate ceiling per account, key, or source, and whether that ceiling actually holds under a modest, controlled burst -- it is a bounded, in-scope check, not a test of whether the endpoint survives a flood. Use this skill when an endpoint has cost, business-logic, or brute-force implications tied to how many times it can be called (login, OTP verification, price lookup, export, password reset) and no rate limit is visible in its responses. Triggers: 'api rate limiting', 'rate limit bypass', 'throttling test', 'request rate ceiling', 'burst request test'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["api"]
tags: ["rate-limiting", "api", "throttling", "abuse-prevention"]
---

# API Rate Limit Testing

## What it is
Rate-limit testing checks whether an API enforces, and correctly enforces, a ceiling on how many times a caller can invoke an endpoint within a given window -- per account, per API key, per IP, or some combination of those. Endpoints tied to cost (a usage-billed downstream call), brute-force risk (login, OTP verification, password reset), or business logic (price lookups, coupon codes, inventory checks) all depend on that ceiling actually holding; a missing or bypassable limit turns a single-request flaw into one that can be repeated at scale.

## Where it shows up
Login and OTP-verification endpoints, password-reset request endpoints, search or export endpoints with a real cost per call, and any endpoint whose response headers never include a rate-limit indicator (`X-RateLimit-*`, `Retry-After`) even after repeated calls are all candidates. Bypass attempts typically target whatever the server uses as the identity key for its limiter -- a source IP that changes if reverse-proxy headers are trusted uncritically, or an account identifier that a header-manipulation trick might spoof.

## How Boundhound approaches it
This is deliberately a bounded, in-scope check, not a denial-of-service test -- Boundhound does not flood an endpoint or attempt to degrade its availability, and the safety layer caps outbound request rates and denies anything resembling a DoS attempt regardless of what is requested. `/enum`'s recon (through `bh-exec`) locates rate-limit-relevant endpoints and any visible limit signals already present in their response headers. Verification is a small, controlled, operator-directed exercise through `/burp`: sending a modest, capped burst of requests -- well below flood volume, decided before testing starts -- to observe whether a limit triggers at all, then testing common bypass techniques (rotating a header the server might trust as the source identity, varying case or encoding of the path, alternating between a couple of test accounts) against that same small budget, all within the scope the Burp MCP guard enforces on every request.

## Scope & safety
Every endpoint tested must already be in `scope.yaml`; the Burp MCP guard denies by default and blocks a request to any host outside scope. The request volume used to probe a limit is fixed and small, and never escalated even if no limit is observed -- confirming the absence of a limit is the finding; proving it by exhausting the endpoint is not the goal and is not something Boundhound will do.

## Remediation
Rate-limit sensitive endpoints per account or API key, not only per source IP, since IP-based limiting alone is trivially bypassed behind a proxy or a botnet of source addresses. Return a standard rate-limit-exceeded response with retry guidance, and validate that any header used to derive client identity for a proxy or CDN cannot be spoofed directly by the client.
