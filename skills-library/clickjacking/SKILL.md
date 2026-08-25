---
name: clickjacking
description: "Clickjacking happens when a page performing a sensitive one-click action lacks framing protection, letting an attacker load it inside a disguised iframe on their own page so a victim's real click lands on the hidden target instead of the attacker's visible decoy. Use this skill when a page missing X-Frame-Options or a frame-ancestors CSP directive performs a state-changing action reachable in a single click. Triggers: 'clickjacking', 'ui redress attack', 'missing x-frame-options', 'frame-ancestors missing', 'iframe overlay attack'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["clickjacking", "web", "ui-redress", "client-side"]
---

# Clickjacking

## What it is
Clickjacking tricks a victim into clicking something on a page they cannot actually see. The target application is loaded inside a transparent or visually disguised iframe on an attacker-controlled page, with deceptive content layered on top. The victim believes they are interacting with the attacker's visible page, but their click actually lands on the hidden, framed target underneath -- potentially triggering a sensitive, state-changing action with a single unwitting click.

## Where it shows up
Any page that performs a sensitive action reachable in one click -- enabling a setting, confirming a transfer, granting a permission, following/subscribing -- and lacks framing protection is a candidate. The absence of an `X-Frame-Options` header, a missing or overly permissive `frame-ancestors` directive in Content-Security-Policy, or reliance on client-side "frame-busting" script (which can itself be bypassed) is the signal to look for.

## How Boundhound approaches it
During `/enum`, nuclei's clickjacking-detection templates (through `bh-exec`) check discovered pages for a missing or overly permissive `X-Frame-Options`/`frame-ancestors` header -- a header-only check that requires no page rendering. ffuf (through `bh-exec`, also `/enum`) helps enumerate the set of pages worth checking, particularly ones with sensitive single-click actions. Confirming actual exploitability -- building a minimal proof-of-concept framing page and observing whether the target genuinely loads inside it and remains clickable -- is manual work done through `/burp` within scope, scope-checked deny-by-default by the Burp MCP guard.

## Scope & safety
Only pages belonging to in-scope hosts in `scope.yaml` are checked. Any proof-of-concept framing page built for verification stays local to the test environment -- it is never hosted publicly or used against a real victim.

## Remediation
Send a restrictive `frame-ancestors` directive in Content-Security-Policy on every page that performs a sensitive action (and `X-Frame-Options: DENY` or `SAMEORIGIN` for older-browser fallback), rather than relying on client-side frame-busting scripts alone.
