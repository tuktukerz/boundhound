---
name: scope-analysis
description: "Reading a program's published rules and turning them into an accurate scope.yaml -- in_scope/out_of_scope domains, wildcards, and CIDRs -- so Boundhound's deny-by-default guard enforces the same boundaries the program actually authorized. Use this skill when starting a new engagement, when a program updates its rules mid-engagement, or when a tool call is unexpectedly denied and the scope definition needs reviewing. Triggers: 'scope analysis', 'scope.yaml', 'in scope out of scope', 'wildcard scope', 'define target scope', 'scope guard denied'."
version: 1.0.0
phase: ["engagement"]
category: ["methodology"]
tags: ["scope", "methodology", "scope.yaml", "authorization", "guard"]
---

# Scope Analysis

## What it is
Scope analysis is the work of turning a program's plain-language rules -- which domains are in play, which are explicitly excluded, whether wildcards or IP ranges are allowed -- into a precise, machine-checkable definition. It happens once, before any tool runs, and it is the single source of truth every later phase re-checks against. Getting this step wrong in either direction is costly: too broad and Boundhound is permitted to touch things the program never authorized; too narrow and legitimate in-scope work gets refused.

## How Boundhound approaches it
`/engagement` asks for the engagement name, authorization (proof of authorization -- a program's own scope page, a signed contract, or a lab/CTF designation), mode, and the in-scope/out-of-scope lists, then writes them into `engagements/<name>/scope.yaml` from the repo's template. The template's structure is `in_scope.domains` and `in_scope.cidrs` alongside `out_of_scope.domains` and `out_of_scope.cidrs`, plus `scope_enforcement` (strict by default), a numeric `rate_limit`, and `safety_constraints` for destructive/DoS behavior. Every phase command re-parses this file and re-screens its candidate hosts against it before running a tool -- recon, enum, and exploit all repeat this check independently rather than trusting an earlier phase's decision.

## Encoding a program's rules correctly
A wildcard entry like `*.example.com` covers subdomains but should be paired with the root domain explicitly if the program includes it. An out-of-scope entry always wins over a broader in-scope wildcard that would otherwise cover it -- list every explicitly excluded subdomain, host, or path the program calls out, even if it looks like it would already match an in-scope wildcard. CIDRs belong in `in_scope.cidrs`/`out_of_scope.cidrs`, not mixed into the domain lists. When a program's rules are ambiguous about a specific subdomain or host, the safer default is to leave it out of `in_scope` and confirm with the program before adding it, rather than guessing broad and letting the guard sort it out later.

## Scope & safety
The scope guard behind `bh-exec` enforces `scope.yaml` deny-by-default: no active scope, an unresolved target, or a target matching `out_of_scope` are all refused before a request goes out, and the refusal is written to the engagement's audit log. This is the same model `bh-burp-scope` mirrors into Burp's own target scope for `/burp` work, and a PreToolUse guard enforces it independently on every Burp MCP call, since that traffic does not pass through `bh-exec` at all -- so the scope defined here is the boundary for every tool in the system, not just the ones that go through `bh-exec` directly.

## Checklist
- Confirm authorization is on record before writing anything else into `scope.yaml`.
- List every explicit out-of-scope exclusion even when it looks redundant against an in-scope wildcard.
- Keep domains and CIDRs in their own respective lists, not combined.
- Re-review `scope.yaml` whenever the program updates its published rules mid-engagement, and re-run `/engagement` or edit the file directly rather than letting phases run against a stale definition.
- Treat an unexpected deny from `bh-exec` as a prompt to re-check the scope definition, not as a bug to work around.
