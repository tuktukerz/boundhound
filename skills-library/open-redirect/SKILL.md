---
name: open-redirect
description: "Open redirect happens when an application redirects to a user-supplied URL or path without validating that the destination stays on the application's own domain, letting an attacker craft a trusted-looking link that ultimately lands the victim on an attacker-controlled site. Use this skill when a redirect, return, next, or callback parameter appears to control where a login, logout, or SSO flow sends the browser next. Triggers: 'open redirect', 'unvalidated redirect', 'redirect parameter abuse', 'oauth redirect_uri bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["open-redirect", "web", "redirect", "client-side"]
---

# Open Redirect

## What it is
Open redirect happens when an application accepts a user-controlled URL or path in a parameter and redirects the browser to it without validating that the destination stays within the application's own domain. An attacker crafts a link that starts on the trusted host -- so it survives casual inspection and link-scanning filters -- but ends by sending the victim's browser to an attacker-controlled site. It is most damaging as a phishing primer and as a way to steal tokens from OAuth/SSO flows that redirect with sensitive values in the URL.

## Where it shows up
Parameters named `redirect`, `return`, `next`, `url`, `continue`, or `callback` on login, logout, and SSO/OAuth flows are the classic pattern -- especially "return to where you were after login" behavior. Endpoints that accept a full URL, a protocol-relative `//host` path, or a path a downstream parser will normalize into an external host are all worth testing, as are `redirect_uri` parameters on OAuth authorization endpoints validated with a loose prefix or substring match.

## How Boundhound approaches it
During `/enum`, nuclei's open-redirect detection templates (through `bh-exec`) probe discovered redirect-style parameters with known bypass payloads and check whether the response actually redirects off-host, while ffuf (through `bh-exec`, also `/enum`) helps enumerate candidate parameters across the target's routes. A flagged candidate is confirmed manually through `/burp` -- submitting a controlled, harmless external marker URL and observing the actual redirect response -- scope-checked deny-by-default by the Burp MCP guard.

## Scope & safety
Only in-scope hosts and parameters from `scope.yaml` are probed, and every verification redirect target is an already-controlled, harmless marker URL -- never a live phishing destination or a domain outside the engagement's control.

## Remediation
Validate redirect destinations against an explicit allow-list of paths or hosts instead of trusting user input directly. Where an external redirect is legitimate (an OAuth callback, a partner link), match the full URL exactly against a registered value and show an interstitial naming the destination rather than redirecting silently.
