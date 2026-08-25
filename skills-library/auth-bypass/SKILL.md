---
name: auth-bypass
description: "Authentication bypass covers any technique that lets a request reach an authenticated resource or action without ever satisfying the login or session check meant to gate it -- a route reachable by an alternate path or HTTP verb the check does not cover, a client-supplied header trusted as proof of identity, or a multi-step login flow where a later step can be reached directly. Use this skill when a protected endpoint might be reachable without a valid session, or when a request header/parameter appears to influence whether an auth check runs at all. Triggers: 'auth bypass', 'authentication bypass', 'login bypass', 'unauthenticated access', 'direct endpoint access', 'access control check missing'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["auth-bypass", "authentication", "access-control", "web"]
---

# Authentication Bypass

## What it is
Authentication bypass covers any technique that lets a request reach an authenticated resource or action without ever satisfying the login or session check meant to gate it. It differs from stolen-credential attacks: the attacker exploits a hole in the check itself -- a missing check for certain paths, an endpoint reachable by a different HTTP verb, a parameter that flips an "authenticated" flag, or logic that trusts a client-supplied header instead of re-verifying the session server-side.

## Where it shows up
Endpoints reachable by an alternate path or verb that the login check never covers (a POST-only auth filter while the same route also accepts GET), API routes mounted at a different base path than the web UI, forwarded-header-style fields or cookies a backend trusts as proof of identity without validating them, default or backup admin routes, and multi-step login flows where a later step can be reached directly, skipping an earlier factor.

## How Boundhound approaches it
Auth bypass is a logic flaw with no single bounded tool that detects or exploits it end to end -- Boundhound is explicit about that instead of implying automated coverage. During `/enum`, ffuf and nuclei (through `bh-exec`) map the full set of routes and parameters a target exposes, including alternate paths, verbs, and headers a login check might miss, and nuclei's known-misconfiguration templates flag a subset of bypass patterns where a matching template exists. Confirming an actual bypass -- requesting a protected endpoint unauthenticated, or with a manipulated header, verb, or parameter, and observing whether the check was actually skipped -- is manual, operator-directed work through `/burp`, scope-checked by the Burp MCP guard on every request.

## Scope & safety
Every endpoint probed for a bypass must resolve to a target already listed in `scope.yaml`; requests outside scope are refused before they are sent, both through `bh-exec` during `/enum` and through the Burp MCP guard's deny-by-default check during `/burp`. Verification uses the minimum number of requests needed to demonstrate the check was skipped -- Boundhound confirms the bypass, it does not chain it into further access.

## Remediation
Re-verify authentication server-side on every request to a protected resource, regardless of path, verb, or header -- never let a filter or gateway rule stand in as the only check. Centralize the auth check so a newly added route inherits it automatically, and treat any header or cookie asserting identity as untrusted until validated against a real session.
