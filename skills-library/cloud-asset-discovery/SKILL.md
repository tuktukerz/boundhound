---
name: cloud-asset-discovery
description: "Cloud asset discovery is finding an organization's cloud-hosted storage and infrastructure -- object storage buckets, blob containers, and similarly named cloud resources -- guessed or derived from the organization's name, domain, and known naming conventions, since a bucket left without access control can expose its entire contents to anyone who finds its name. Use this skill when a target's cloud footprint (rather than its web application) needs mapping, or when an organization is known to rely on cloud-hosted storage. Triggers: 'cloud asset discovery', 'exposed storage bucket', 'bucket enumeration', 'cloud misconfiguration recon', 'blob storage exposure'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["cloud", "storage-bucket", "osint", "misconfiguration"]
---

# Cloud Asset Discovery

## What it is
Cloud providers let customers create object storage (buckets, blob containers) with a name of their choosing, and by default many of these resources are reachable at a predictable URL once that name is known. Cloud asset discovery is deriving likely bucket and container names from an organization's name, domain, product names, and common naming conventions (`-prod`, `-backup`, `-assets`, `-dev`), then checking which ones exist and whether they are left readable or writable to anyone. A single misconfigured bucket can expose backups, customer data, or internal documents that were never meant to leave the organization.

## Where it shows up
Backup and archive buckets are the highest-value targets, since they are created for convenience and often forgotten about long after the project that needed them ends. Naming conventions leak information on their own -- a bucket named after an internal product codename or environment (`-staging`, `-internal`) confirms things about the organization's infrastructure before its contents are even examined. Misconfigured access control (public list, public read, or public write) rather than the existence of the bucket itself is almost always the actual finding.

## How Boundhound approaches it
Boundhound has no dedicated bounded tool that generates or brute-forces cloud storage names today -- this playbook is OSINT and naming-convention analysis, not something `/recon` runs automatically. A candidate bucket or container name derived this way is a lead, not a target: it is added to `scope.yaml` and confirmed as belonging to the organization before anything happens to it. Once a candidate resource is in scope, checking whether it resolves and what it exposes is a bounded, read-only check through `/recon`'s httpx probing (through `bh-exec`), rather than a broad automated sweep of every possible name.

## Scope & safety
A cloud provider's storage endpoints are shared, multi-tenant infrastructure -- a name that resolves might belong to an entirely different, unrelated organization, so confirming actual ownership before any check matters more here than in almost any other recon technique. Every check that goes beyond a passive name guess is bounded, read-only, and restricted to resources already confirmed in `scope.yaml`; nothing in this playbook writes to, deletes, or modifies a cloud resource.

## Remediation
Apply least-privilege access control to every storage bucket or container by default -- private unless a specific, reviewed reason requires public access -- and audit existing resources for public read/write permissions regularly. Avoid naming conventions that reveal internal project names, environments, or organizational structure in a publicly-resolvable resource name.
