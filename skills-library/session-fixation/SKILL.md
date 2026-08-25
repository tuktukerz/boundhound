---
name: session-fixation
description: "Session fixation lets an attacker set or predict a victim's session identifier before authentication, then reuse that same identifier after the victim logs in to inherit their authenticated session -- typically because the application accepts an externally supplied session ID and never issues a fresh one at login. Use this skill when a session token or cookie is accepted before login and the same value remains valid, unchanged, after successful authentication. Triggers: 'session fixation', 'session id not rotated', 'session token reuse', 'fixed session cookie', 'session riding'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["session-fixation", "session", "cookie", "authentication", "web"]
---

# Session Fixation

## What it is
Session fixation exploits an application's failure to issue a new session identifier at the moment of authentication. If a session cookie can be set or predicted before login (via a query-string parameter, a cross-domain cookie write, or simply the identifier the server handed out to an anonymous visitor) and that same identifier is still valid and now tied to an authenticated user after login, an attacker who fixed that value ahead of time can use it themselves once the victim signs in.

## Where it shows up
Applications that accept a session ID from a query string or a pre-set cookie, or that never call a session-regeneration step on the login path, are the classic case. Look for a session cookie's value staying byte-for-byte identical across an unauthenticated request and the authenticated response that follows a successful login -- that is the direct signal the session was fixed rather than rotated.

## How Boundhound approaches it
Confirming fixation requires comparing a session identifier's value across an authentication boundary, which is manual verification through `/burp`: capture the pre-login session token, complete login in the same session context, and check whether the token changed. `/enum`'s recon and nuclei templates (through `bh-exec`) can surface cookie-handling metadata such as missing `Secure`/`HttpOnly` flags or session-related misconfigurations where a detection template exists, which helps prioritize which login flows to check by hand in `/burp`. There is no bounded tool in this system that detects session-fixation logic on its own -- Boundhound treats this as operator-verified, not automated.

## Scope & safety
All requests used to capture or replay a session token stay inside `scope.yaml`, enforced by the Burp MCP guard's deny-by-default check before anything is sent to a target outside scope. Verification uses only the engagement's own test accounts and the minimum number of login cycles needed to show the identifier did not rotate -- Boundhound does not attempt to fixate or hijack a real end user's session.

## Remediation
Always issue a brand-new session identifier immediately after a successful authentication, invalidating whatever identifier the client held before login. Reject session identifiers supplied via URL parameters, and scope session cookies tightly (`HttpOnly`, `Secure`, an appropriate `SameSite` value) so they cannot be set or read cross-origin.
