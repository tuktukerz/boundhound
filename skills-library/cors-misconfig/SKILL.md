---
name: cors-misconfig
description: "CORS misconfiguration happens when a server's Cross-Origin Resource Sharing headers grant more trust than intended -- reflecting an arbitrary request Origin back in Access-Control-Allow-Origin, especially alongside Access-Control-Allow-Credentials: true -- letting a malicious page read authenticated responses across origins. Use this skill when an API reflects the Origin header verbatim, allows a wildcard alongside credentials, or uses an overly broad origin allow-list. Triggers: 'cors misconfiguration', 'access-control-allow-origin reflected', 'cors credentials wildcard', 'cross-origin resource sharing bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["cors", "web", "misconfiguration", "client-side"]
---

# CORS Misconfiguration

## What it is
CORS misconfiguration occurs when a server's Cross-Origin Resource Sharing response headers grant a browser running attacker-controlled script permission to read a response it should never see. The most serious pattern is reflecting an arbitrary request `Origin` back verbatim in `Access-Control-Allow-Origin` while also setting `Access-Control-Allow-Credentials: true` -- together, that combination lets any site read authenticated responses on a victim's behalf, since the browser will attach the victim's cookies to the cross-origin request.

## Where it shows up
APIs that dynamically reflect the request's `Origin` header instead of checking it against a fixed list, a wildcard `*` combined with credentialed requests, allow-lists implemented with a weak substring or regex match on the origin (matching `evil-example.com` because it contains `example.com`), and `null`-origin handling that trusts sandboxed iframes or local files.

## How Boundhound approaches it
During `/enum`, nuclei's CORS-misconfiguration detection templates (through `bh-exec`) check discovered endpoints by sending a probe `Origin` header and inspecting the response for reflected-origin and wildcard-plus-credentials patterns -- a fast, header-only check with no state change. ffuf (also through `bh-exec`, `/enum`) helps enumerate the API surface worth checking. A flagged finding is confirmed manually through `/burp`: replay the request with a chosen `Origin` in Repeater and confirm both the response headers and whether a credentialed cross-origin read actually succeeds, scope-checked deny-by-default by the Burp MCP guard.

## Scope & safety
Only hosts listed in `scope.yaml` are probed with alternate `Origin` headers. Manual verification through `/burp` goes only as far as showing that a crafted origin obtains an authenticated response tied to an already-authorized test account -- no real third-party data is read or exfiltrated during the check.

## Remediation
Return a static, explicit allow-list of trusted origins instead of reflecting the request's `Origin`, and pair `Access-Control-Allow-Credentials: true` only with a validated, non-wildcard origin drawn from that list. Treat `null` and unrecognized origins as untrusted by default.
