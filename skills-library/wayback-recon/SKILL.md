---
name: wayback-recon
description: "Wayback recon is mining publicly archived, historical snapshots of a target's web pages to recover old URLs, parameters, and content that no longer exist on the live site -- retired endpoints, old API routes, and pages removed for exposing something they should not have. Use this skill when a target's current site map might be missing endpoints and parameters that existed at some point in its history and were never properly decommissioned server-side. Triggers: 'wayback recon', 'archived url discovery', 'historical url enumeration', 'web archive recon', 'old endpoint discovery'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["web-archive", "historical-urls", "osint", "passive-recon"]
---

# Wayback Recon

## What it is
Public web-archiving services periodically crawl and store snapshots of pages across the internet, including a target's site as it existed months or years ago. Wayback recon is querying that historical record for a target's domain to recover URLs, parameters, and content that no longer exist on the current live site -- endpoints that were retired, API routes that were replaced, or pages pulled down specifically because they exposed something they should not have. None of it requires sending the current site a single request; the entire technique reads from a third party's historical archive.

## Where it shows up
Old API routes and parameters recovered this way sometimes still work against the current backend even though nothing on the live site links to them anymore -- the frontend changed, but the endpoint was never actually decommissioned. Pages removed after exposing sensitive information (an internal document, a misconfigured directory listing, a debug page) sometimes remain fully readable in an archived snapshot even though the live version is long gone. Parameter names harvested from years of archived URLs also build a useful wordlist for testing today's version of the same application.

## How Boundhound approaches it
Boundhound has no bounded tool that queries public web archives today -- this playbook is passive OSINT, not something `/recon` runs automatically. Every query in this technique goes to a third-party archive, never the target, so nothing here touches scope on its own. Once a historical URL or parameter is recovered, it is only tested against the live target after it is confirmed to still resolve and has been added to `scope.yaml`; `/recon`'s httpx probing (through `bh-exec`) is the first step that actually reaches the target, and only for endpoints that have cleared scope.

## Scope & safety
Archive queries touch only the third-party archiving service, never the organization being assessed, so this playbook carries no risk to the target on its own. The risk is entirely downstream: a recovered URL is a historical lead, not a live target, and it is confirmed live and added to `scope.yaml` before any request built from it is actually sent.

## Remediation
Properly decommission retired endpoints server-side rather than only removing their frontend links -- an endpoint that still responds is still reachable no matter how it was found. Request removal of archived snapshots that captured genuinely sensitive content, and avoid assuming that "no longer linked" is equivalent to "no longer accessible."
