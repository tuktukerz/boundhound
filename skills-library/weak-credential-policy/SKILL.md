---
name: weak-credential-policy
description: "Weak credential policy covers an application accepting passwords that are short, common, or otherwise easy to guess -- no minimum length or complexity requirement, no check against known-breached or common-password lists, and no protection against many password guesses against one account. Use this skill when reviewing a registration or password-change form's accepted password strength, or an account's exposure to guessing due to missing lockout or throttling. Triggers: 'weak password policy', 'password complexity', 'no lockout', 'password strength check', 'account lockout policy'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["password-policy", "credentials", "lockout", "authentication", "web"]
---

# Weak Credential Policy

## What it is
A weak credential policy is a gap in what an application requires and enforces around passwords, not a flaw in the login logic itself: no meaningful minimum length or complexity requirement, no rejection of common or previously breached passwords, and no lockout, delay, or challenge after repeated failed attempts on a single account. Any one of these makes an individual account meaningfully easier to guess into; together they make the account boundary the weakest part of the system.

## Where it shows up
Registration forms, password-change forms, and the login endpoint's failure-handling behavior are where this is assessed -- what the application accepts when a password is set, and what happens, or does not happen, after several consecutive failed login attempts against one account.

## How Boundhound approaches it
This is a policy-review task, not something a bounded tool exploits -- Boundhound checks what a registration or change form accepts and how a login endpoint reacts to repeated failures, on the engagement's own test account only. `/enum`'s recon (through `bh-exec`) locates the registration, password-change, and login endpoints to review. Confirming the actual policy -- attempting to set a deliberately weak password, and observing whether a handful of controlled failed logins on the test account trigger a lockout, delay, or challenge -- is manual, operator-directed verification through `/burp`, within the scope the Burp MCP guard enforces. Boundhound does not run bulk password-guessing or brute-force attempts against any account, test or otherwise, to prove the missing lockout beyond what a small, controlled sample shows -- that kind of mass attack is explicitly out of scope for this playbook and for the system as a whole.

## Scope & safety
Every endpoint reviewed and every login attempt made stays inside `scope.yaml` and uses only the engagement's own test account; nothing outside scope is touched. The number of deliberately failed logins used to observe lockout behavior is kept to the minimum needed to see whether a control exists at all -- this playbook documents a policy gap, it does not carry out a credential attack.

## Remediation
Require a minimum password length -- length matters more than forced complexity rules -- and check new passwords against a list of common or previously breached values. Add a lockout, exponential delay, or challenge after a small number of consecutive failed attempts on an account, and rate-limit the login endpoint itself independent of any single account's history.
