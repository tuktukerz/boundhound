---
name: tech-fingerprinting
description: "Tech fingerprinting is identifying the web servers, frameworks, CMS platforms, and libraries a target is running by examining response headers, page titles, status codes, and other observable artifacts, since knowing what a target is actually built on turns a blind test into one that can be aimed at known weaknesses for that specific stack. Use this skill early against any discovered live host, before deciding which later techniques are worth prioritizing. Triggers: 'tech fingerprinting', 'technology detection', 'stack identification', 'framework detection', 'server banner grabbing'."
version: 1.0.0
phase: ["recon"]
category: ["recon-osint"]
tags: ["fingerprinting", "httpx", "technology-detection", "recon"]
---

# Tech Fingerprinting

## What it is
Tech fingerprinting is identifying what software a target host actually runs -- web server, framework, CMS, common libraries, and their versions where observable -- from artifacts a normal request already returns: response headers, page titles, favicon hashes, default error pages, and status-code behavior. It turns an anonymous list of live hosts into a list of hosts with known technology, which is what lets later phases prioritize checks that matter for that specific stack instead of running every possible test against every host equally.

## Where it shows up
`Server` and `X-Powered-By` headers, when present, name the web server and sometimes the framework directly. Page titles and default landing pages frequently give away a CMS or admin panel by name before any deeper interaction happens. Status codes on common framework-default paths (a redirect, a 403 instead of a 404, a distinctive error page) reveal a stack even when headers have been deliberately stripped.

## How Boundhound approaches it
During `/recon`, Boundhound runs httpx (through `bh-exec`) with technology-detection, title, and status-code flags (`-td -title -sc`) against every live host confirmed by earlier probing. This produces a per-host technology profile in a single lightweight pass -- no separate crawl or extra requests beyond the probe `/recon` was already making -- that later phases use to decide which checks are worth prioritizing for that specific host.

## Scope & safety
httpx's technology-detection pass is a normal, read-only request no different from a browser loading the page, and it only runs against hosts already confirmed in `scope.yaml` through `bh-exec`'s deny-by-default enforcement. Fingerprinting results inform prioritization; they are never treated as confirmation of a vulnerability on their own -- an identified framework version is a lead for further, properly scoped verification, not a finding by itself.

## Remediation
Avoid leaking version numbers in banners and error pages where practical, and keep frameworks, CMS platforms, and libraries patched regardless of whether their identity is exposed -- fingerprinting resistance is a minor speed bump, not a substitute for staying current. Assume that a determined attacker can identify the stack through behavior alone even when headers are stripped, and prioritize patching accordingly.
