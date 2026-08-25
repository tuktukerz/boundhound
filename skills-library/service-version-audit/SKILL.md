---
name: service-version-audit
description: "Service-version auditing is comparing the exact service and version banners a scan returns against publicly known issues affecting that specific version, since the version string is often the fastest available signal for whether a listening service is running long-outdated software. Use this skill after a scan returns service and version detail on an in-scope host worth checking against known issues for that version. Triggers: 'service version audit', 'version banner check', 'outdated service detection', 'known vulnerable version', 'nmap version detection'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["infra-network"]
tags: ["version-detection", "nmap", "nuclei", "service-audit", "network"]
---

# Service Version Audit

## What it is
Every network service that answers a connection tends to identify itself, at least partially -- a banner, a header, a response format specific to one product's implementation of a protocol. Service-version auditing takes that identification and checks it against what is publicly known to affect that specific version, turning a bare "port is open" observation into a specific, actionable lead: this exact version, on this exact service, has documented issues worth confirming.

## Where it shows up
Any exposed service with a legible version banner is a candidate, but the highest-value findings tend to be infrastructure that is patched rarely -- network appliances, database engines, and management interfaces that keep running for years once installed. A version several releases behind current is worth flagging even before any specific known issue is confirmed against it, simply because the gap itself signals a patching process that is not keeping up.

## How Boundhound approaches it
During `/recon`, nmap's service/version detection (through `bh-exec`) is central to this: a TCP connect scan (`-sT`) with no host-discovery ping sweep (`-Pn`) and a moderate, non-aggressive timing template (`-T3`) against a fixed, defined port set, run against every confirmed in-scope host. For web-facing services, httpx contributes complementary title, status, and technology detail during the same phase. During `/enum`, nuclei's version-aware templates (through `bh-exec`) check identified services and versions against templates recognizing known, named issues, surfacing candidates for confirmation. Anything a version banner reveals that has no matching template is a manual correlation step against public advisories for that exact version, not something Boundhound checks automatically today.

## Scope & safety
Version identification itself is a normal, read-only part of connecting to a service -- no different from what any client does on connection -- and it only runs against hosts already confirmed in `scope.yaml`, refused otherwise by `bh-exec`'s deny-by-default enforcement. A template match or version comparison is a lead requiring confirmation, not a finding reported as fact on its own.

## Remediation
Patch and upgrade exposed services to supported, current versions promptly rather than treating a stable but outdated version as safe by inertia, and track vendor advisories for anything already deployed. Do not rely on hiding version banners as a substitute for actually staying current -- it slows identification, not exploitation of a version that is genuinely vulnerable.
