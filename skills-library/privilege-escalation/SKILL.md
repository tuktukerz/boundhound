---
name: privilege-escalation
description: "Privilege escalation is what happens once broken access control or IDOR is successfully exploited: a user ends up with more capability than their account was granted, either by acting as a different user at the same privilege level (horizontal) or by gaining a higher privilege level entirely (vertical), such as a standard account reaching admin-only functionality. Use this skill when a lower-privilege account performs an action, or reaches a resource, that should require a different account or a higher role. Triggers: 'privilege escalation', 'vertical privilege escalation', 'horizontal privilege escalation', 'role elevation', 'admin bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-access-control"]
tags: ["privilege-escalation", "access-control", "authorization", "role", "web"]
---

# Privilege Escalation

## What it is
Privilege escalation is the outcome, not the mechanism -- it is what an attacker achieves by chaining an access-control weakness (a missing check, an IDOR, a trusted client-side role value) into gaining capability their account should not have. Horizontal escalation reaches another user's data or actions at the same nominal privilege level; vertical escalation reaches a higher role's actions entirely, such as a normal user performing an admin action.

## Where it shows up
Role or permission fields accepted from the client (a role value in a request body, cookie, or token claim that the server does not re-validate), account-switching or "act as" features, admin functionality reachable by guessing or reusing an endpoint pattern from the regular user flow, and any workflow where a lower-privilege session can reach a higher-privilege state transition, such as approving its own request or promoting its own account.

## How Boundhound approaches it
Privilege escalation is a logic and authorization outcome, not something a single bounded tool exploits automatically -- Boundhound does not claim otherwise. The safe workflow starts the same way as broken access control and IDOR: `/enum` uses ffuf and recon output (through `bh-exec`) to map the endpoints and role-gated functionality a target exposes, so the candidate admin or elevated-privilege surfaces are known. Confirming that a lower-privilege account can actually reach one of those surfaces is manual and operator-directed through `/burp` -- issuing the request from a lower-privilege test session and confirming whether the elevated action succeeds, entirely within the Burp MCP guard's scope check.

## Scope & safety
All accounts and endpoints used in verification belong to the engagement and are already covered by `scope.yaml`; the Burp MCP guard denies by default and blocks anything outside scope before a request goes out. Boundhound confirms escalation is possible with the smallest action that proves it, such as reading an admin-only page, and does not use an escalated session to make further changes beyond that proof.

## Remediation
Re-check role and permission server-side at every privilege boundary, never trusting a client-supplied role claim; treat every state-changing or elevated action as its own authorization decision rather than assuming a valid session implies the right to perform it. Log and alert on privilege-boundary requests from unexpected roles as a detective control.
