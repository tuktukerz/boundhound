---
name: ssl-tls-audit
description: "SSL/TLS auditing is checking a target's TLS configuration -- certificate validity and chain, supported protocol versions, and known TLS-implementation misconfigurations -- since a weak or outdated TLS setup can downgrade an otherwise-secure connection to one an attacker can intercept, tamper with, or use to impersonate the server. Use this skill against any host or service confirmed to serve TLS once it is live and in scope, whether that is HTTPS or another TLS-wrapped service. Triggers: 'ssl audit', 'tls misconfiguration', 'certificate validation', 'weak cipher suite', 'ssl/tls scan', 'deprecated tls version'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["infra-network"]
tags: ["tls", "ssl", "certificate", "nmap", "httpx", "nuclei"]
---

# SSL/TLS Audit

## What it is
TLS auditing examines the handshake and certificate a service presents rather than its application logic: which protocol versions it still accepts, whether its certificate is valid, correctly chained, and matches the hostname being served, and whether its configuration matches any publicly known, template-detectable TLS misconfiguration. A service can be otherwise well-built and still leave every connection to it downgradable or impersonable because of a stale TLS setting nobody revisited.

## Where it shows up
Expired, self-signed, or hostname-mismatched certificates are the most common finding, usually the result of a renewal process that quietly stopped working. Deprecated protocol versions and weak cipher suites left enabled for compatibility with old clients that no longer exist are the next most common, and plain HTTP still being served where HTTPS should be enforced is worth flagging on its own.

## How Boundhound approaches it
During `/recon`, nmap's service/version detection (through `bh-exec`) identifies which ports on an in-scope host are serving TLS and can surface certificate and protocol detail directly at the network layer, while httpx (also through `bh-exec`) separately confirms TLS status, response title, and status code for HTTP(S) targets, flagging a host serving plain HTTP where HTTPS should be enforced. During `/enum`, nuclei's TLS and misconfiguration templates (through `bh-exec`) check discovered hosts against known, named issues -- expired or mismatched certificates, deprecated protocol versions, and similar template-recognizable misconfigurations -- surfacing candidates for confirmation rather than performing an exhaustive manual cipher-suite audit.

## Scope & safety
Every host checked must already be confirmed in `scope.yaml`; a TLS handshake and certificate read is a normal, read-only connection no different from a browser loading the page, and `bh-exec` refuses to dispatch against anything outside scope. Template-flagged issues are leads for confirmation, not findings on their own -- a template match against a specific configuration is verified before being reported as an actual weakness.

## Remediation
Disable deprecated protocol versions and weak cipher suites, keep certificates current and correctly chained well before their expiry, and enforce HTTPS with an appropriate redirect and strict-transport policy wherever a service accepts both plain and encrypted connections. Automate certificate renewal rather than relying on a manual process to catch expiry in time.
