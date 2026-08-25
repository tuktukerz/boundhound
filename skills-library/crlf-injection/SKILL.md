---
name: crlf-injection
description: "CRLF injection occurs when user input containing carriage-return/line-feed sequences reaches a raw HTTP header or log line without sanitization, letting an attacker inject additional headers, split the response into two, or forge log entries -- often used as a stepping stone to response splitting, cache poisoning, or header-based attacks. Use this skill when a parameter's value is reflected into a response header (a redirect Location, a Set-Cookie value, a custom header) or written into an application log. Triggers: 'crlf injection', 'http response splitting', 'header injection', 'log injection', 'carriage return line feed'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["crlf", "header-injection", "response-splitting", "web", "injection"]
---

# CRLF Injection

## What it is
CRLF injection exploits the fact that HTTP headers are separated by carriage-return/line-feed pairs. If a header value is built from user input without stripping or encoding those characters, an attacker can inject the sequence to terminate the current header and start a new one -- adding arbitrary headers, setting extra cookies, or, in the worst case, splitting the response into two so a fabricated second response is delivered to the browser or an intermediary cache.

## Where it shows up
Anywhere a parameter feeds directly into a response header is a candidate: redirect endpoints where the Location header is built from a query parameter, features that let a user set a custom header or cookie value, and endpoints whose input is written into a plain-text log file (log injection is the same root cause, applied to logs instead of headers). An encoded carriage-return/line-feed sequence in the input producing an extra header or a visibly split response is the confirming signal.

## How Boundhound approaches it
`/enum` runs nuclei's CRLF/header-injection detection templates (through `bh-exec`) against discovered endpoints, and ffuf (through `bh-exec`, also `/enum`) helps enumerate parameters that end up in response headers when they aren't already known. Manual verification happens through `/burp`: an encoded carriage-return/line-feed probe is sent via Repeater and the raw response headers are inspected for the injected line. Every `/burp` call passes through the Burp MCP scope guard, deny-by-default like `bh-exec`.

## Scope & safety
Only in-scope hosts and parameters from `scope.yaml` are probed. Verification injects a single, clearly-marked extra header or line purely to prove the injection is possible -- Boundhound does not use CRLF injection to poison shared caches or forge production log entries as part of this skill.

## Remediation
Strip or reject carriage-return and line-feed characters from any value placed into a header, and rely on the web framework or HTTP library's header-setting API (which typically encodes or rejects these characters automatically) rather than building raw header strings. Apply the same input handling to values written into logs to prevent log injection.
