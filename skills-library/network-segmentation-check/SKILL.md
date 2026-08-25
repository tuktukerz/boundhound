---
name: network-segmentation-check
description: "Network segmentation checking is testing whether network zones that are supposed to be isolated from each other -- for example a public-facing perimeter zone and an internal management network -- are actually unreachable from one another, by looking for hosts and services answering across a boundary that should block them, since a broken segmentation boundary turns a single compromised host into a path toward everything behind it. Use this skill when the engagement's scope spans hosts declared in more than one distinct network zone or segment. Triggers: 'network segmentation', 'segmentation testing', 'vlan isolation check', 'lateral movement path', 'zone boundary check'."
version: 1.0.0
phase: ["recon"]
category: ["infra-network"]
tags: ["segmentation", "network-zones", "nmap", "isolation", "network"]
---

# Network Segmentation Check

## What it is
Segmentation is the architectural practice of splitting a network into zones with different trust levels -- a public-facing perimeter, an internal application tier, a management network -- and restricting what can reach what between them. Checking it means testing whether that isolation actually holds in practice, not just whether a diagram or a firewall ruleset claims it does: a host in one zone answering to a scan run from another zone it should be unreachable from is exactly the gap this looks for.

## Where it shows up
Any environment that claims a perimeter-versus-internal split, distinct VLANs for different trust levels, or a management network kept isolated from production traffic is making a segmentation claim worth testing. The gap usually comes from a firewall rule added for a one-off need and never removed, or a host with an extra network interface that quietly bridges two zones that were never meant to be able to reach each other.

## How Boundhound approaches it
Boundhound has no topology-aware segmentation-testing tool today. What `/recon`'s nmap pass (through `bh-exec`) offers is comparing the port and service map returned for hosts declared in different zones within `scope.yaml`: reachability observed from wherever the scan runs is informative, but a single-vantage-point scan cannot on its own prove a boundary is intact -- it can only show what was reachable from where the scan happened to run. A genuine segmentation test, scanning from within each declared zone toward the others, needs either a dedicated bounded tool or agent placed in each zone -- brought into the system through `bh-exec` with its own scope and safety review -- or manual, operator-directed testing performed from within each zone in turn.

## Scope & safety
Every host scanned, from whatever vantage point, must already be confirmed in `scope.yaml`, and nmap's bounded flag set (a TCP connect scan, no aggressive timing) keeps any per-zone pass predictable rather than resembling a stress test against infrastructure that segmentation rules were meant to protect. A positive cross-zone reachability finding is significant enough to report immediately, since it reflects a gap in an architectural control rather than an isolated application bug.

## Remediation
Enforce boundary controls -- firewall rules and access-control lists -- between every declared zone, and default to deny between zones rather than allow-by-default with specific exceptions. Re-test reachability across zone boundaries on a schedule rather than once at design time, since rules accumulate and drift over the life of a network far more often than architecture diagrams get updated to match.
