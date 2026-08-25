---
name: xss-reflected
description: "Reflected cross-site scripting occurs when untrusted input from a single request (a query-string parameter, form field, or header) is echoed back into the response HTML without proper encoding, letting an attacker craft a link or form submission that executes arbitrary script in the victim's browser session. Use this skill when a parameter's value appears to be reflected verbatim into the page -- error messages, search-result headers, and pre-filled form fields are the classic locations. Triggers: 'reflected xss', 'cross-site scripting', 'xss', 'script injection', 'reflected script injection'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["xss", "reflected", "client-side", "web", "injection"]
---

# Reflected Cross-Site Scripting

## What it is
Reflected XSS is an injection flaw where a request parameter is echoed back into the HTML response without encoding or sanitization, so a specially crafted URL or form submission causes the victim's browser to execute attacker-supplied script in the context of the vulnerable site. Unlike stored XSS, the payload lives in the request itself and only affects whoever is tricked into submitting it.

## Where it shows up
Search boxes that echo the search term ("no results for `<query>`"), error pages that repeat an invalid input, and pre-filled form values sourced from the query string are the most common locations. Any parameter whose value shows up verbatim in the returned HTML, and that isn't obviously encoded, is worth testing with a harmless marker payload.

## How Boundhound approaches it
During `/enum`, nuclei's XSS detection templates (through `bh-exec`) scan discovered endpoints and parameters for reflected-injection patterns. Alongside that, ffuf (through `bh-exec`, also part of `/enum`) is used to discover parameters and endpoints worth testing when they aren't already known from crawling. Once a candidate is flagged, manual verification happens through `/burp` -- loading the request into Repeater and confirming the payload executes unescaped in the reflected response. Every `/burp` call is scope-checked by the Burp MCP guard, which is deny-by-default the same way `bh-exec` is for bounded tools.

## Scope & safety
Only hosts and parameters listed in `scope.yaml` are tested; anything else is refused before a request is sent. Verification uses non-destructive marker payloads (e.g., an inert string or a harmless alert/console-log call) solely to prove script execution -- never a payload that persists, exfiltrates data, or pivots further.

## Remediation
Context-aware output encoding (HTML-entity encoding for HTML bodies, JS-string encoding inside script blocks, attribute encoding inside tag attributes) closes reflected XSS. A strict Content-Security-Policy is a strong second layer of defense.
