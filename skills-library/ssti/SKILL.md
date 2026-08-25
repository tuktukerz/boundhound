---
name: ssti
description: "Server-side template injection happens when user input is concatenated into a server-side template string before that template is rendered, letting an attacker inject template syntax that the template engine evaluates -- ranging from information disclosure up to full remote code execution depending on the engine. Use this skill when an application appears to process input through a templating engine (dynamic emails, reports, user-customizable pages) rather than treating it as plain data. Triggers: 'server-side template injection', 'ssti', 'template injection', 'template engine evaluation', 'template engine rce'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["ssti", "template-injection", "rce", "web", "injection"]
---

# Server-Side Template Injection

## What it is
SSTI arises when untrusted input is embedded directly into a template's source (rather than passed in as a data variable) before the template engine renders it. Because template syntax is designed to execute logic, an attacker who controls part of the template source can often go well beyond simple output manipulation -- reading server-side variables, and on several popular engines, reaching arbitrary code execution.

## Where it shows up
Look for input that ends up somewhere a templating engine would process it: customizable email/notification templates, dynamically generated reports or invoices, "preview my page" features, and any parameter whose value seems to be evaluated rather than just displayed. A classic low-risk confirmation probe is a math expression such as a multiplication wrapped in the engine's expression delimiters -- if the response shows the computed product instead of the literal expression, the input is being evaluated by a template engine.

## How Boundhound approaches it
`/enum` runs nuclei's SSTI detection templates (through `bh-exec`) against discovered endpoints, and ffuf (through `bh-exec`, also `/enum`) helps surface parameters and endpoints worth probing when they aren't already known. Manual verification happens through `/burp`: a math-expression probe is sent via Repeater and the response is checked for evaluation, then, only if further impact needs proving within scope, engine-specific but non-destructive follow-up probes are tried the same way. Every `/burp` call passes through the Burp MCP scope guard, deny-by-default like `bh-exec`.

## Scope & safety
Testing stays limited to hosts and parameters in `scope.yaml`. Confirmation probes are limited to read-only expressions (arithmetic, or reading an already-known-safe variable) -- Boundhound does not chain SSTI findings into code execution or file access as part of this skill; that would require a separate, explicitly scoped exploitation step.

## Remediation
Never build template source strings from untrusted input; pass user data in as template variables/context instead of as template syntax. Where a templating feature must accept some user-authored logic, use the engine's sandboxed-rendering mode if one exists, and keep the engine and its sandbox up to date.
