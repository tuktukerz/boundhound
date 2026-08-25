---
name: host-header-injection
description: "Host header injection happens when an application trusts the client-supplied Host header (or a forwarding header such as X-Forwarded-Host) for security-relevant logic -- building password-reset links, generating absolute URLs, or routing/caching decisions -- without validating it against the expected hostname, letting an attacker substitute a header value that redirects victims to an attacker-controlled domain or poisons a cache entry. Use this skill when password-reset emails, generated links, or routing behavior appear to be influenced by the request's Host header. Triggers: 'host header injection', 'host header attack', 'password reset poisoning', 'x-forwarded-host injection', 'host header manipulation'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["host-header", "web", "injection", "cache-poisoning"]
---

# Host Header Injection

## What it is
Host header injection exploits applications that use the Host header (or a forwarding header like X-Forwarded-Host) as a trusted source of the application's own hostname, rather than validating it against a known, expected value. Because the Host header is fully attacker-controlled on a raw HTTP request, trusting it for anything security-sensitive -- generating a password-reset link, building an absolute redirect URL, making a routing or cache-key decision -- lets an attacker substitute their own domain into that logic.

## Where it shows up
Password-reset and email-verification flows that embed a link built from the request's host are the highest-impact case: submitting an arbitrary Host value and seeing it reflected into the reset link's domain confirms the issue. Absolute-URL generation (canonical links, redirect targets, API base URLs) and any behavior that seems to change when a forwarding header differs from the actual Host are also worth checking, since the latter often signals a caching or load-balancer layer trusting the wrong header.

## How Boundhound approaches it
`/enum` runs nuclei's host-header-injection detection templates (through `bh-exec`) against discovered endpoints, and ffuf (through `bh-exec`, also `/enum`) helps enumerate endpoints -- particularly password-reset and link-generation flows -- worth testing. Manual verification happens through `/burp`: send a request with a modified Host or forwarding-header value via Repeater and confirm whether that value is reflected into a generated link, redirect, or cache behavior. Every `/burp` call passes through the Burp MCP scope guard, deny-by-default like `bh-exec`.

## Scope & safety
Only in-scope hosts from `scope.yaml` are tested, and any substituted Host value used for verification points at an already-controlled, harmless marker domain -- never a real third-party domain that could receive live traffic or credentials as a side effect of the test. No actual password-reset request is sent to a real account outside the engagement's authorized test accounts.

## Remediation
Never derive security-sensitive URLs or logic from the Host or forwarding-header value; use a server-side configuration value for the application's canonical hostname instead. Where a forwarding header must be trusted (behind a load balancer), validate it against an explicit allow-list of expected values.
