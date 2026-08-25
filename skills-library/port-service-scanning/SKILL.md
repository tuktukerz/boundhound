---
name: port-service-scanning
description: "Port and service scanning is identifying which network ports are open on a target host and what service (and version, where determinable) is listening on each one, forming the map of network-reachable surface that later phases decide what to do with. Use this skill against any confirmed in-scope host or IP once web-focused recon alone is not enough -- exposed non-web services, unexpected open ports, and outdated service versions are all found here first. Triggers: 'port scanning', 'service scanning', 'nmap scan', 'open port discovery', 'service version detection'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["port-scan", "nmap", "service-detection", "network-recon"]
---

# Port & Service Scanning

## What it is
Port and service scanning determines which TCP ports on a host respond at all, and what is actually listening on each open one -- an SSH daemon, a database, a mail service, or an unexpected admin interface never intended to be reachable from outside. It is the network-layer counterpart to web-focused recon: subdomain enumeration and tech fingerprinting map what a target serves over HTTP, while port scanning maps everything else a host exposes on the network.

## Where it shows up
Non-web services (databases, remote administration, mail, file sharing) directly reachable from the internet are consistently high-value findings, since they are often configured with the assumption that only internal traffic would ever reach them. An unexpected open port on a host otherwise known only for its website is a strong signal worth investigating on its own. Outdated service versions, once identified, feed directly into checking for known issues affecting that specific version.

## How Boundhound approaches it
During `/recon`, Boundhound runs nmap (through `bh-exec`) against confirmed in-scope hosts using a deliberately bounded flag set: a TCP connect scan (`-sT`), no host-discovery ping sweep (`-Pn`), and a moderate, non-aggressive timing template (`-T3`) against a fixed, defined port set rather than every possible port. Aggressive or high-noise flags -- `-T5` and equivalent maximum-speed timing, full 1-65535 sweeps, and disruptive fingerprinting flags -- are excluded from what Boundhound requests by default, keeping the scan predictable and low-impact rather than fast at any cost.

## Scope & safety
Every host and IP scanned must already be in `scope.yaml`; `bh-exec` refuses to dispatch nmap against anything outside scope before a single packet goes out. The bounded flag set is a deliberate safety choice, not just a performance one -- a fixed port set and moderate timing keep the scan from behaving like a stress test against infrastructure that might be fragile, and results are treated as a map of surface to investigate further, not as confirmation that any given service is vulnerable.

## Remediation
Close or firewall any port and service that does not need to be reachable from the network the scan was run from, especially administrative and database services that should never be internet-facing. Keep exposed services patched and on supported versions, since an accurate version identification is exactly what turns an open port into an actionable finding for an attacker.
