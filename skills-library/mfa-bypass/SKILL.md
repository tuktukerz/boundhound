---
name: mfa-bypass
description: "MFA bypass covers techniques that let an attacker complete authentication while skipping or defeating a second factor -- reaching a post-login page directly without ever supplying the second factor, an OTP verification endpoint with no rate limit, a 'remember this device' cookie that can be forged or replayed, or a response manipulation the client trusts instead of the server enforcing state. Use this skill when a login flow has a distinct second-factor step (OTP, push, authenticator code) that might be reachable, forgeable, or skippable. Triggers: 'mfa bypass', '2fa bypass', 'otp bypass', 'second factor bypass', 'remember device bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["mfa", "2fa", "otp", "authentication", "web"]
---

# MFA Bypass

## What it is
Multi-factor authentication adds a second check after the first factor (usually a password) succeeds, and bypass techniques target the seam between those two steps rather than either factor individually. Common patterns: the application sets an "authenticated" session state after the first factor and only checks for the second factor on the client side, so a post-login endpoint can be reached directly; the OTP verification endpoint has no rate limit or lockout, making a short numeric code brute-forceable; a "remember this device" or "trusted device" cookie is predictable, unsigned, or accepted without being tied to the specific account; or the verification response itself can be manipulated because the server trusts the client's report of success instead of checking its own state.

## Where it shows up
Any login flow with a visible, distinct second-factor step -- an OTP entry page, a push-approval wait screen, a backup-code field -- is a candidate. The endpoint that issues the "authenticated" session or token, whichever step that happens at, and the OTP-submission endpoint's rate-limiting behavior are the two places worth checking first.

## How Boundhound approaches it
MFA bypass is a sequencing and rate-limiting flaw with no single bounded tool that detects or exploits it end to end. `/enum` uses ffuf and nuclei (through `bh-exec`) to map the login and verification endpoints involved and flag a subset of known misconfigurations where a matching template exists. Confirming whether a post-first-factor endpoint is reachable without completing the second factor, or whether the OTP endpoint actually rate-limits, is manual verification through `/burp` -- a small number of controlled requests against the engagement's own test account, within the scope the Burp MCP guard enforces. Boundhound explicitly does not run bulk OTP-guessing or brute-force attempts against a live second factor; that crosses into the credential-attack territory documented separately and is out of scope for this playbook.

## Scope & safety
Every endpoint tested stays inside `scope.yaml`, refused before any request is sent if it falls outside; the Burp MCP guard enforces this on every `/burp` request. Verification against a rate limit uses the smallest number of attempts needed to observe whether a lockout or throttle triggers, and never continues into a real brute-force run -- Boundhound stops at proving the gap, not exploiting it further.

## Remediation
Enforce the second factor server-side as a hard gate on session elevation -- the session should not become "authenticated" until both factors are verified, and every subsequent request should be checked against that server-side state rather than a client-reported flag. Rate-limit and lock out OTP verification attempts, and bind "remember this device" tokens to both the account and the device with a signed, unpredictable value.
