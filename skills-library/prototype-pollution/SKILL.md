---
name: prototype-pollution
description: "Prototype pollution happens when untrusted input reaches a deep-merge, clone, or property-assignment operation that lets an attacker set properties on Object.prototype itself -- through keys like __proto__ or constructor.prototype -- affecting every object in the runtime that inherits from it. Use this skill when a JSON-accepting endpoint or client-side merge utility appears to process nested, attacker-controlled keys without rejecting prototype-chain property names. Triggers: 'prototype pollution', '__proto__ injection', 'constructor.prototype pollution', 'object.prototype pollution'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["prototype-pollution", "javascript", "client-side", "web"]
---

# Prototype Pollution

## What it is
Prototype pollution is a JavaScript-specific flaw where attacker-controlled input -- a JSON body, query string, or URL fragment merged into an existing object by a vulnerable deep-merge, clone, or assignment routine -- is used to set a property on `Object.prototype` itself, via a key such as `__proto__` or `constructor.prototype`, or a nested chain that reaches one of those. Because every plain object in the runtime inherits from `Object.prototype`, a single polluted property can silently change behavior across the entire application, not just the object the input was meant to configure. Depending on where the polluted property is later read, impact ranges from denial of service, to bypassing a property-based access check, to remote code execution in specific frameworks.

## Where it shows up
Endpoints and client-side code that merge untrusted JSON into an existing object -- query-string-to-object parsers, generic deep-clone/merge utility functions, template engines that resolve arbitrary property paths, and configuration-loading code that accepts nested keys straight from user input. A parameter or JSON key containing `__proto__` or `constructor.prototype` that causes an unrelated part of the application to behave differently is the classic signal that a merge is unguarded.

## How Boundhound approaches it
Prototype pollution has no bounded tool in Boundhound today -- there is no nuclei template or scanner wired in through `bh-exec` that reliably detects it, and this is stated plainly rather than implying automated coverage that does not exist. ffuf (through `bh-exec`, during `/enum`) still helps enumerate the JSON-accepting endpoints and parameters worth reviewing by hand. From there, testing is entirely manual through `/burp` within scope: submit a `__proto__`- or `constructor.prototype`-keyed payload to a candidate endpoint or client-side sink and, using Repeater and the browser console, observe whether an unrelated object gained the injected property -- all under the Burp MCP guard's scope check.

## Scope & safety
Testing is limited to endpoints and pages already inside `scope.yaml`, checked through the Burp MCP guard's deny-by-default enforcement on every request. Verification payloads set a harmless, easily identified marker property -- never one chosen to trigger a real denial-of-service condition or downstream code execution on a live system.

## Remediation
Freeze `Object.prototype` where feasible, use `Object.create(null)` or a `Map` for user-controlled key/value structures, and reject or strip keys named `__proto__`, `constructor`, or `prototype` before any merge or assignment operation touches untrusted input.
