---
name: ldap-injection
description: "LDAP injection occurs when user input is concatenated into an LDAP search filter without escaping the filter's special characters, letting an attacker alter the filter's logic to bypass authentication or enumerate directory entries beyond what the application intended to expose. Use this skill when an application authenticates against or searches an LDAP/Active-Directory-backed directory and builds its filter string from user-supplied values (username fields, directory search boxes). Triggers: 'ldap injection', 'ldap filter injection', 'directory injection', 'directory auth bypass', 'ldap auth bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["ldap-injection", "directory", "web", "injection"]
---

# LDAP Injection

## What it is
LDAP injection abuses the fact that LDAP search filters are built as strings with their own special characters (wildcards, parentheses, backslashes, boolean operators). If a filter is assembled by directly concatenating user input -- for example, a filter that checks both a username and a password field -- an attacker can inject filter syntax of their own, most commonly to turn an authentication check into an always-true condition or to widen a search filter and enumerate directory entries.

## Where it shows up
Login forms and user-lookup/search features backed by an LDAP or Active-Directory directory are the target. Submitting a value containing filter metacharacters (a leading wildcard for a broad match, or a sequence that closes and reopens filter clauses) and observing authentication succeed unexpectedly, or a search return far more entries than a literal match would, is the classic signal.

## How Boundhound approaches it
Boundhound does not currently have a bounded tool that detects or exploits LDAP injection -- nuclei's template coverage for this technique is minimal since it is highly specific to how a given application builds its filter string, so `/enum` cannot be relied on here, and this skill states that plainly rather than overclaiming. The safe path is manual verification through `/burp`: within scope, submit filter-metacharacter payloads to a login or search field via Repeater and observe whether the directory query's behavior changes (unexpected authentication success, or a broadened result set). A dedicated bounded LDAP-injection tool can be brought in through `bh-exec` in a future phase.

## Scope & safety
Testing is limited to in-scope endpoints from `scope.yaml`. Verification probes aim to prove the filter's logic can be altered -- authentication-bypass probes are attempted only against accounts already authorized for testing under the engagement's scope, never against arbitrary directory accounts, and no bulk directory enumeration is performed as part of this proof step.

## Remediation
Escape LDAP filter metacharacters in any value before it is placed into a filter string, or use the directory library's parameterized filter-building API if one is available. Apply least-privilege bind accounts for application-level LDAP queries so a successful injection has limited reach.
