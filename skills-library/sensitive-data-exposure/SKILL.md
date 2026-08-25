---
name: sensitive-data-exposure
description: "Sensitive data exposure is an application returning more than it should in a response it already sends to any caller -- internal identifiers, credentials or tokens, personal information, configuration values, or internal hostnames -- because a field was never trimmed, an error was never sanitized, or client-side code shipped a secret that was only meant to live server-side. Use this skill when a response body, header, or client-side asset appears to carry data beyond what the calling client legitimately needs. Triggers: 'sensitive data exposure', 'information leakage', 'exposed credentials in response', 'pii leak', 'data exposure'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["info-disclosure"]
tags: ["sensitive-data", "information-disclosure", "httpx", "nuclei", "web"]
---

# Sensitive Data Exposure

## What it is
Sensitive data exposure is not a new access path being forced open -- it is an application handing over more than it should through a channel it already uses legitimately. A full user object returned when only a display name was needed, an internal token embedded in a client-side bundle, a config value echoed back in a response -- in every case the server already decided to send the data; the flaw is that it decided to send too much of it. That distinction matters for how it is confirmed: proving this class of issue is about reading what a normal request already returns, not about coercing the server into revealing something new.

## Where it shows up
API responses that return an entire internal record when the client only renders a few fields, hardcoded API keys or tokens shipped inside client-side JavaScript, HTML comments left in from development, cached or autocomplete data that leaks a previous user's input, and headers or metadata that expose internal hostnames, file paths, or software versions. Endpoints that were built for an internal caller and later exposed externally without re-checking their response shape are a common source.

## How Boundhound approaches it
During `/recon` and `/enum`, httpx (through `bh-exec`) captures full response bodies and headers for discovered endpoints, and nuclei's exposure templates (also through `bh-exec`) flag responses matching known patterns for leaked keys, tokens, or internal metadata. Where a response looks suspicious but doesn't match a template, manual review through `/burp` inspects the specific response within scope to judge whether the data actually exceeds what the endpoint's caller needs. Every step here is passive observation of data the target already returned to an authorized test request -- the work is confirming that something is exposed, not collecting or exfiltrating it.

## Scope & safety
Every host and endpoint reviewed must already be listed in `scope.yaml`; `bh-exec` refuses anything outside scope before a request goes out. When exposure is confirmed, Boundhound records the field, pattern, and just enough context to prove the finding -- it does not retain or forward the full sensitive payload beyond what is needed to demonstrate the issue to the engagement owner.

## Remediation
Return only the fields a caller actually needs -- an explicit response shape or allow-list beats trusting that internal fields will never matter to an external client. Keep secrets and tokens out of client-side code entirely, strip development comments and debug fields before deployment, and review headers and error paths for anything that leaks internal infrastructure detail.
