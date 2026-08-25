---
name: csrf
description: "Cross-site request forgery (CSRF) happens when a state-changing endpoint accepts a request authenticated only by ambient credentials (cookies) without verifying that the request was intentionally made by the user, letting an attacker's page trigger requests a victim's browser will submit automatically. Use this skill when a form or API action changes state using only cookie-based session auth, with no unique per-request token or origin check. Triggers: 'csrf', 'cross-site request forgery', 'csrf token missing', 'state-changing get request', 'samesite cookie bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["csrf", "web", "session", "client-side"]
---

# Cross-Site Request Forgery

## What it is
CSRF forces a logged-in victim's browser to submit a state-changing request to a target application without the victim's intent, riding on the session cookie the browser attaches automatically to any request. It exploits the trust a server places in ambient authentication -- "this request carried a valid session cookie" -- rather than in a per-request proof that the user actually meant to make that specific call.

## Where it shows up
State-changing endpoints (account settings, password or email change, funds transfer, adding an admin user) that rely solely on cookie-based sessions without a unique, server-validated token per request are the primary target. Endpoints that perform a state change on a GET request are a worse variant, since they need no form submission at all -- an image tag or a link is enough. Missing or non-`Strict`/`Lax` `SameSite` cookie attributes, and a server that never checks `Origin` or `Referer` on sensitive actions, are both supporting signals.

## How Boundhound approaches it
No single bounded tool automates CSRF discovery end to end. During `/enum`, ffuf (through `bh-exec`) helps enumerate a target's state-changing endpoints and forms so candidates for review are known up front. Confirming an actual CSRF exposure -- building a cross-origin proof-of-concept request and observing whether the server accepts it without a valid, unpredictable token, or checking whether `SameSite`/`Origin`/`Referer` enforcement actually blocks it -- is manual, operator-directed work done through `/burp`, scope-checked deny-by-default by the Burp MCP guard on every request.

## Scope & safety
Every endpoint tested must resolve to a target already listed in `scope.yaml`. Proof-of-concept requests exercise a benign, reversible state change against an already-authorized test account -- never a real user's live session -- and stop as soon as the missing check is demonstrated.

## Remediation
Require a unique, unpredictable, server-validated token on every state-changing request, bound to the session and rejected outright if missing or mismatched. Set session cookies with `SameSite=Lax` or `Strict`, and validate `Origin`/`Referer` on sensitive actions as defense in depth rather than as the sole control.
