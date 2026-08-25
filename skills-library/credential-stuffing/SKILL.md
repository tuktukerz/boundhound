---
name: credential-stuffing
description: "Credential stuffing is the mass, automated submission of username/password pairs leaked from other services' breaches against a login endpoint, relying on password reuse across sites rather than any flaw in this particular application. Use this skill when assessing whether a login endpoint has the defenses (rate limiting, anomaly detection, bot mitigation) needed to resist automated bulk-login attempts -- not for actually mounting one. Triggers: 'credential stuffing', 'password reuse attack', 'bulk login attempt', 'automated login testing', 'breached credential list'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["credential-stuffing", "rate-limiting", "authentication", "web"]
---

# Credential Stuffing

## What it is
Credential stuffing takes username/password pairs leaked from breaches of other, unrelated services and submits them en masse against a target's login endpoint, betting on the fact that people reuse passwords across sites. It is not an application vulnerability in the traditional sense -- the target application did nothing wrong to leak those credentials -- but the target's login endpoint is what determines whether that reused-password bet pays off at scale: strong rate limiting, anomaly detection, and bot mitigation make bulk attempts expensive and detectable; their absence makes the login endpoint an easy target for lists built from unrelated breaches.

## Where it shows up
Any public login endpoint is exposed to this by definition. What varies is defensive posture: per-account and per-source rate limiting, a challenge triggered by unusual request volume or velocity, device or location anomaly checks, and whether failed-login responses leak enough detail (for example, distinguishing "wrong password" from "account does not exist") to help an attacker validate which usernames in a list are real accounts.

## How Boundhound approaches it
Boundhound does not perform credential stuffing or any bulk/automated multi-account login attack -- there is no bounded tool in this system for mass credential attacks, and none will be wired in for this purpose. What this playbook covers instead is assessing the target's resistance to that class of attack: `/enum`'s recon (through `bh-exec`) locates the login endpoint and any visible rate-limit or bot-mitigation signals in its responses. Any deeper check -- for example, whether a small, controlled handful of failed logins from the engagement's own test account triggers a lockout, delay, or challenge -- is manual, operator-directed verification through `/burp`, within the scope the Burp MCP guard enforces on every request, and stays limited to that small sample rather than any attempt to run or simulate an actual stuffing attack.

## Scope & safety
Only the engagement's own test account is used for any login-defense check, and the number of attempts is kept to the minimum needed to observe whether a control triggers; nothing resembling a real bulk-login run against real accounts is performed, in or out of scope. Every request made still stays inside `scope.yaml`, refused before it is sent if the target falls outside. This playbook's output is a finding about defensive posture -- present or absent rate limiting, anomaly detection, account-enumeration leakage -- not a credential-stuffing attack result.

## Remediation
Rate-limit login attempts per account and per source, and add anomaly detection or a challenge triggered by unusual volume or velocity. Normalize failed-login responses so they do not reveal whether a submitted username exists, and offer or require multi-factor authentication so a correct password alone is insufficient even when reuse succeeds.
