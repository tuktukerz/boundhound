---
name: bug-bounty-workflow
description: "The end-to-end path Boundhound follows for a bug bounty engagement, from recorded authorization to a submitted write-up: /engagement to fix scope.yaml, /recon to map the surface, /enum to find candidates, /exploit for bounded proof, /verify to confirm, /report to render the write-up -- or /fullscan to run the whole chain in one pass. Use this skill when starting a new engagement, deciding what to run next, or explaining how the phases fit together. Triggers: 'bug bounty workflow', 'engagement lifecycle', 'what command comes next', 'fullscan vs manual phases', 'end-to-end pentest flow', 'bounty program methodology'."
version: 1.0.0
phase: ["engagement", "recon", "enum", "exploit", "verify", "report"]
category: ["methodology"]
tags: ["workflow", "methodology", "engagement", "lifecycle", "fullscan"]
---

# Bug Bounty Workflow

## What it is
A bug bounty engagement is a single authorized target program worked through a fixed set of phases, each one producing a structured artifact the next phase reads. The workflow is not "run every tool at once" -- it is a deliberate chain where scope is fixed before anything fires, and every later step is constrained by what an earlier step already confirmed. Treating the phases as a sequence, rather than a grab-bag of tools, is what keeps an engagement both efficient and safe.

## The Boundhound flow
The chain runs in one direction: `/engagement` records authorization and writes `scope.yaml` (in-scope domains/CIDRs, out-of-scope exclusions, rate limit, safety constraints) -- nothing downstream runs without this. `/recon` discovers subdomains and live hosts and writes `recon-map.json`. `/enum` reads that map, re-screens every host against the current scope, and probes for content and misconfigurations into `enum-map.json`. `/exploit` reads both maps, re-screens again, and produces bounded, non-destructive proof-of-vulnerability into `exploit-map.json`. `/verify` consolidates everything into `findings.json` and re-runs each candidate's original bounded check to confirm it still holds. `/report` renders the final `report.md` from that verified data. `/fullscan` runs recon through report as one pass (optionally skipping exploit with `--no-exploit`) and supports `--resume` for a long-running engagement -- it is a convenience over the same phases, not a different pipeline.

## Scope & safety
`scope.yaml` is authored once, at the start, and every phase re-reads it rather than trusting an earlier phase's screening -- a host that was in scope during `/recon` gets re-checked again at `/enum` and `/exploit`, since scope can change between phases. Every tool invocation in every phase -- subfinder, httpx, nmap, ffuf, nuclei, sqlmap -- runs through `bh-exec`, which enforces this deny-by-default scope model plus rate limiting and destructive/DoS-flag denial, and logs the decision. Nothing in this workflow calls a scanning tool directly; a command that cannot get its work done through `bh-exec` does not do it another way.

## Steps
1. Run `/engagement` first: name the engagement, record authorization, and fill `in_scope`/`out_of_scope` in `scope.yaml`.
2. Run `/recon` to build `recon-map.json` from the in-scope domains.
3. Run `/enum` to build `enum-map.json` from the live hosts recon found.
4. Run `/exploit` for bounded proof-of-vulnerability on candidates with testable parameters (skip this step for a non-intrusive engagement).
5. Run `/verify` to consolidate `findings.json` and re-confirm every candidate.
6. Run `/report` to render `report.md`, then use it as the basis for the submission write-up.
7. For a routine engagement, `/fullscan` performs steps 2-6 in one pass; fall back to the manual phases whenever a step needs closer inspection, a paused/resumed run, or a non-default flag set.

## When to prefer manual phases over fullscan
Run phases manually when you need to inspect an intermediate map before continuing, when the engagement's rules call for exploit to be skipped entirely, or when only one phase needs to be re-run (for example, re-running `/enum` after the program adds a subdomain mid-engagement). `/fullscan` is the right choice for a first pass through a fresh, well-defined scope where every phase should run without a pause in between.
