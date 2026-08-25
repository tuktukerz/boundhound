---
name: severity-triage
description: "Reading the severity, confidence, and verified fields Boundhound's /verify and /report phases assign to each finding -- critical, high, medium, low, or info -- and using that model to decide what needs attention first and what belongs in a submission. Use this skill when reviewing findings.json, deciding which findings to write up first, or explaining why two findings of the same type carry different severities. Triggers: 'severity triage', 'findings.json', 'critical high medium low', 'verified vs confirmed', 'triage findings', 'severity ranking'."
version: 1.0.0
phase: ["verify", "report"]
category: ["methodology"]
tags: ["severity", "methodology", "triage", "findings", "verify"]
---

# Severity Triage

## What it is
Severity triage is the discipline of ranking findings by actual impact so limited time goes to the issues that matter most, instead of treating every result from a scan as equally worth writing up. It runs after data collection, not during it -- recon and enum surface raw observations, and only once a finding is understood well enough to grade does triage become meaningful.

## Boundhound's severity model
`/verify` builds `findings.json` by consolidating recon, enum, and exploit output through a fixed, table-driven rule: an open port, an exposed HTTP service, a discovered subdomain, or a piece of discovered content is always `info` -- it is an observation, not a graded weakness, until something specific about it is confirmed. A nuclei-sourced finding carries whatever severity the matching template assigned (`critical` through `info`); an unrecognized or missing severity value safely falls back to `info` rather than being invented. A confirmed SQL injection from `/exploit` is always `high`. Each finding also carries a `confidence` of `reported` (from recon/enum) or `confirmed` (from `/exploit`, or after `/verify`'s re-check reproduces it), and a `verified` flag that starts `false` and flips to `true` only once the re-check confirms it. These fields are the whole model -- triage means reading them, not re-deriving severity by eye.

## How to triage
Sort by severity first (`critical`, `high`, `medium`, `low`, `info` -- the same order `/report` groups by), then within a severity band prioritize `verified:true` findings over `verified:false` ones, since a verified finding is confirmed to still hold and an unverified one might not reproduce. A `critical` or `high` finding that is also `verified:true` is the top of the queue for a submission; an `info`-severity observation (an open port, a live host) is context for the report, not a standalone submission on its own merit. Never manually re-rank a finding's severity in `findings.json` by hand -- if a severity looks wrong, the fix is to check the source data (the nuclei template's own rating, or whether the type-to-severity rule applies correctly), not to override the file.

## Scope & safety
Triage only ever operates on findings that already passed through the scope guard during recon/enum/exploit -- a finding for an out-of-scope target should never appear in `findings.json` in the first place, since every phase re-screens its candidates against `scope.yaml` before running. If an out-of-scope finding somehow appears, treat it as a scope-analysis bug to fix, not something to triage and report.

## Checklist
- Read severity, confidence, and verified together -- never one field in isolation.
- Work critical/high verified findings first, then critical/high unverified, then medium and below.
- Leave `info`-severity findings in the report as supporting context rather than dropping them.
- Escalate a finding whose severity looks miscalculated by checking the source rule, not by hand-editing `findings.json`.
