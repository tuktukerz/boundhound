---
name: forced-browsing
description: "Forced browsing is the technique of directly requesting resources -- pages, files, or API endpoints -- that are not linked from the application's normal navigation, on the assumption that leaving something unlinked is enough to keep it private. Use this skill when a target likely has admin panels, backup files, staging endpoints, or draft content that is not reachable through the visible site but might still resolve if requested directly. Triggers: 'forced browsing', 'unlinked resource discovery', 'hidden endpoint access', 'directory guessing', 'unpublished page access'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["web-access-control"]
tags: ["forced-browsing", "content-discovery", "hidden-resources", "web"]
---

# Forced Browsing

## What it is
Forced browsing treats "not linked in the interface" as the weak, and false, assumption it is. Many applications rely on obscurity rather than an actual access check to keep an admin panel, a staging page, a backup file, or draft content away from users -- forced browsing is simply requesting the resource directly by guessing or discovering its path, and checking whether it resolves without the access control the application relied on omission to provide.

## Where it shows up
Predictable admin or staging paths, backup and configuration file names left alongside deployed code, draft or unpublished content reachable by predictable ID even though it is not listed anywhere, and any resource whose only protection is that its URL was never published.

## How Boundhound approaches it
This is squarely what `/enum` is built for: ffuf (through `bh-exec`) runs wordlist-driven content discovery against a target to surface exactly the unlinked paths, files, and directories that forced browsing would otherwise require manual guessing for, and nuclei's exposure templates flag known-sensitive paths where a matching template exists. Where a discovered resource looks like it should require authentication or a role check but does not, confirming that gap is manual, through `/burp` -- requesting the path directly and observing whether the expected restriction is actually enforced.

## Scope & safety
Content discovery only targets hosts already listed in `scope.yaml`; ffuf's request volume and rate stay within the bounds `bh-exec` enforces for the engagement, and anything outside scope is refused before a request is sent. Once a resource is discovered, Boundhound reads only as much as is needed to confirm whether it should have been protected -- it does not use forced browsing to harvest the contents of every discovered file.

## Remediation
Never rely on an unpublished or unlinked URL as an access control -- every sensitive resource needs an explicit authentication and authorization check enforced server-side, regardless of whether its path is guessable. Remove backup files, staging endpoints, and draft content from production-reachable paths entirely rather than leaving them unlinked but live.
