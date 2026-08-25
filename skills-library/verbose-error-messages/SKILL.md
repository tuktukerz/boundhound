---
name: verbose-error-messages
description: "Verbose error messages happen when an application returns a raw stack trace, a database error, or an internal exception detail to the client instead of a generic failure response, revealing framework and library versions, internal file paths, query structure, or configuration detail that helps an attacker plan further attacks. Use this skill when an unexpected input, malformed request, or edge case produces a response that looks like unfiltered debug output rather than a normal error page. Triggers: 'verbose error message', 'stack trace disclosure', 'debug output leak', 'unhandled exception response', 'error-based information leak'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["info-disclosure"]
tags: ["verbose-errors", "error-handling", "httpx", "nuclei", "web"]
---

# Verbose Error Messages

## What it is
A verbose error message is what an application shows when it fails without first deciding what a stranger should be allowed to see. Instead of a generic failure page, the client receives a raw stack trace, a database driver's error text, or an internal exception dump -- content that was written for a developer reading logs, not for an untrusted caller reading a response. On its own it is rarely the full vulnerability, but it routinely hands over the framework, library versions, internal file paths, or query structure that make every other technique easier to aim.

## Where it shows up
Malformed input, unexpected types, missing required fields, and requests that hit an edge case the application never explicitly handled are the most reliable way to trigger one. A response that suddenly contains a stack trace, a full file-system path, a database error naming a table or column, or a framework's default debug page is the signal -- especially when it differs sharply from the application's normal, sanitized error handling.

## How Boundhound approaches it
During `/enum`, nuclei's misconfiguration and exposure templates (through `bh-exec`) probe for known debug-page and stack-trace patterns triggered by common malformed requests, while httpx (also through `bh-exec`) captures the full response body and status code for anything discovered so a verbose error is visible rather than inferred from a status code alone. Where a candidate response needs closer reading -- distinguishing a genuinely leaked internal detail from a merely unusual but sanitized error page -- that judgment call is made manually through `/burp`, within scope. This is read-only observation of a response the target already generated; Boundhound does not craft payloads intended to crash a service, only ordinary malformed input that a real user could plausibly send by accident.

## Scope & safety
Only hosts and endpoints already listed in `scope.yaml` are probed, and `bh-exec` enforces that boundary deny-by-default. Triggering an error is limited to non-destructive malformed input -- never input designed to exhaust resources, corrupt state, or degrade availability -- and a template match is treated as a lead to confirm, not a finding to report outright.

## Remediation
Return a generic, fixed error response to clients in production and log the full detail server-side instead, so debugging information never leaves the trust boundary. Disable framework debug modes and default exception pages before deployment, and review error-handling paths the same way normal application logic is reviewed, since they are just as reachable by an attacker.
