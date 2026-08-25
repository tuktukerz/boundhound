---
name: password-reset-poisoning
description: "Password-reset poisoning manipulates a password-reset flow's host-related input -- the Host header, a forwarded-host header, or a reset-link parameter -- so the reset email sent to the victim contains a link pointing at an attacker-controlled domain, letting the attacker capture the reset token when the victim clicks it. Use this skill when a forgot-password flow builds its emailed reset link from request-derived host data rather than a fixed, trusted value. Triggers: 'password reset poisoning', 'host header poisoning', 'reset token leak', 'forgot password vulnerability', 'reset link manipulation'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["password-reset", "host-header", "authentication", "web"]
---

# Password-Reset Poisoning

## What it is
Password-reset poisoning abuses the fact that a forgot-password flow typically builds the link inside its reset email using the incoming request's host information rather than a hardcoded value. If the application trusts the `Host` header, a forwarded-host header, or a similar client-supplied field when constructing that link, an attacker who submits the reset request with a manipulated host causes the victim's own reset email to contain a link pointing at a domain the attacker controls -- and the reset token travels there when the link is clicked.

## Where it shows up
Any forgot-password or account-recovery form is a candidate, especially applications running behind a reverse proxy or load balancer where the backend is already expected to read the original host from a forwarded header. The tell is a reset email whose link domain changes when the request's `Host` or forwarded-host header is changed, rather than staying fixed to the application's real domain.

## How Boundhound approaches it
This is a header-trust and email-construction flaw with no single bounded tool that detects or exploits it end to end. `/enum` and nuclei (through `bh-exec`) can flag a subset of known host-header-trust misconfigurations where a matching template exists, and recon establishes where the password-reset endpoint lives. Actually triggering a reset request with a manipulated host header and inspecting the resulting email content is manual verification through `/burp`, using the engagement's own test account and mailbox, within the scope the Burp MCP guard enforces on every request.

## Scope & safety
The password-reset endpoint tested must already be in `scope.yaml`; requests outside scope are refused before they are sent. Verification triggers a reset only for the engagement's own test account and observes the resulting email -- Boundhound never triggers a reset for a real, unrelated account, and does not follow a poisoned link to actually take over an account beyond confirming the link's domain was attacker-controlled.

## Remediation
Build password-reset links from a fixed, server-side-configured domain -- never from `Host`, a forwarded-host header, or any other client-supplied header. If a reverse proxy must forward host information, validate it against an allowlist before the application trusts it for anything security-sensitive, including link construction.
