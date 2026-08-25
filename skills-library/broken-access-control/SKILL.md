---
name: broken-access-control
description: "Broken access control is the general category of authorization failures where an application allows an authenticated, or even unauthenticated, user to reach data, functions, or administrative actions that should be restricted to a different user or role. It covers missing or misconfigured checks anywhere a request should be gated by identity or role -- a hidden admin endpoint with no server-side check, a client-side-only permission hint, or an API method that never verifies role at all. Use this skill when a control (a menu item, a button, an API route) appears to exist for one role only, but might be reachable directly regardless of role. Triggers: 'broken access control', 'authorization bypass', 'missing function level access control', 'unrestricted admin endpoint', 'access control misconfiguration'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-access-control"]
tags: ["access-control", "authorization", "broken-access-control", "web"]
---

# Broken Access Control

## What it is
Broken access control describes any case where the server fails to enforce who is allowed to do what. It is the umbrella term that covers IDOR, privilege escalation, and forced browsing, but it also includes standalone failures such as a function that trusts a client-supplied role flag, an admin action reachable by any authenticated session because no server-side role check exists, or a missing check that lets an unauthenticated request reach an endpoint that was meant to require a session at all.

## Where it shows up
Anywhere the interface hides a control from a role but the underlying endpoint does not enforce the same restriction: admin panels linked only from an admin's navigation, bulk-action or export endpoints, internal APIs assumed to be reachable only from a trusted front end, and role or permission values passed in a request body, cookie, or hidden field that the server trusts instead of re-deriving server-side.

## How Boundhound approaches it
Like IDOR and privilege escalation, broken access control is a logic and authorization category with no single bounded tool that detects or exploits it end to end -- Boundhound states that plainly rather than implying otherwise. The safe workflow: `/enum` uses ffuf (through `bh-exec`) against recon output to map the full set of endpoints a target exposes, including ones no interface links to, and nuclei's exposure-related templates flag a subset of known misconfiguration patterns where a matching template exists. From there, confirming that a specific endpoint or function lacks the access check it should have is manual, through `/burp` -- requesting the endpoint directly with a lower-privilege or unauthenticated session and comparing the result against the expected restriction.

## Scope & safety
Endpoint discovery and verification both stay inside `scope.yaml`; the Burp MCP guard denies by default and refuses to send a request to a host outside scope. Verification uses the minimum request needed to show the missing check -- Boundhound confirms the gap exists, it does not chain the finding into further exploitation.

## Remediation
Enforce authorization centrally and server-side -- every request handler should re-derive the caller's role or permissions from a trusted session and check it against the action being performed, rather than trusting client-supplied role data or relying on the interface to hide a control. Default to deny and require an explicit grant for sensitive actions.
