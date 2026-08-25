---
name: google-dorking
description: "Google dorking is using a search engine's own advanced/operator syntax -- site:, filetype:, intitle:, inurl:, and similar -- to surface pages, files, and misconfigurations a target has published and a search engine has indexed, without ever sending the target a single request. Use this skill when a target's own indexed footprint -- exposed documents, login portals, error pages, or configuration files a search engine has crawled -- might reveal more than its official site map does. Triggers: 'google dorking', 'search engine dorking', 'advanced search operators', 'indexed sensitive files', 'dork query'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["dorking", "search-operators", "osint", "passive-recon"]
---

# Google Dorking

## What it is
Search engines index far more of a target's public footprint than its official navigation links to: forgotten PDFs, exposed login portals, misconfigured directory listings, error pages that leak a stack trace, and files that were never meant to be crawled but were reachable when a search engine's bot passed by. Google dorking is the practice of using a search engine's own advanced operators -- restricting results to a specific site, file type, page title, or URL pattern -- to surface that indexed material deliberately instead of stumbling onto it by accident. Nothing about the technique touches the target directly; every query goes to the search engine, not the organization being assessed.

## Where it shows up
`site:` combined with `filetype:` finds exposed spreadsheets, configuration backups, and documents that were uploaded without realizing they were publicly reachable and crawlable. `intitle:` and `inurl:` operators surface login portals, admin panels, and default framework pages that a target never intended to be discoverable outside a direct URL. Cached and indexed error pages sometimes outlive the bug that caused them, revealing internal paths or stack traces long after the live page has been fixed.

## How Boundhound approaches it
Boundhound has no bounded tool that runs search-engine dork queries -- this is manual, analyst-driven passive OSINT, not something `/recon` executes automatically. Nothing in this playbook sends a request to the target; it only queries a public search engine's existing index. Any host, exposed document, or path a dork query turns up is a lead, not a target -- it must be added to `scope.yaml` and confirmed as belonging to the engagement before `/recon`'s httpx probing (through `bh-exec`) or any active tool goes anywhere near it.

## Scope & safety
Because every query in this playbook is sent to a search engine rather than the target, it carries zero risk of alerting or affecting the organization being assessed. The discipline that matters here is on the other end: a dork result naming a host or path outside the engagement's approved root domains is documented and set aside, never treated as an in-scope target just because a search engine indexed it.

## Remediation
Use `robots.txt`, authentication, and correct HTTP status codes to keep sensitive documents and internal pages out of search engine indexes in the first place, and request de-indexing promptly for anything found exposed. Review what a search engine has indexed for the organization periodically -- an old file removed from a site can still be reachable through a cached or archived copy.
