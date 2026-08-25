---
name: report-writeup
description: "Using /report (which runs bh-report to render findings.json and scope.yaml into report.md, complete with a severity-count table and per-type remediation) as the basis for a program submission write-up. Use this skill when an engagement is ready to report, when turning report.md into an individual submission per finding, or when explaining why the report only ever contains verified engagement data. Triggers: 'report writeup', 'report.md', 'bh-report', 'submission writeup', 'remediation table', 'write up a finding'."
version: 1.0.0
phase: ["report"]
category: ["methodology"]
tags: ["report", "methodology", "writeup", "remediation", "bh-report"]
---

# Report Write-Up

## What it is
The write-up is the last step of an engagement: turning verified findings into a document a program can act on. A good write-up is specific and evidence-backed -- what was tested, what was found, why it matters, and how to fix it -- rather than a raw tool dump. Boundhound's reporting phase is built around never inventing any of that content; it only ever renders what earlier phases already confirmed.

## How Boundhound approaches it
`/report` requires `output/verify/findings.json` to already exist -- it will not run ahead of `/verify`. It calls `bh-report`, which reads that findings file plus the engagement's `scope.yaml` and renders `output/report/report.md`: engagement metadata, a severity-count table (critical through info), the count of verified findings, and every finding grouped by severity with its own remediation guidance drawn from a fixed, per-type table (parameterized queries for sqli, patch-or-upgrade guidance for a nuclei template, firewall/necessity review for an open port, and so on -- falling back to generic vulnerability-management guidance for any type the table doesn't cover by name). If the scope itself is broken, `bh-report` fails closed rather than rendering a report from bad data, and the operator is expected to fix scope before trying again.

## Turning report.md into a submission
`report.md` is the source of truth for a program submission, not a draft to be rewritten from memory: pull each finding's severity, target, evidence, and remediation text directly from it rather than re-describing the vulnerability from recollection. For programs that want one submission per finding rather than one combined report, split `report.md`'s per-finding sections into individual write-ups, keeping each finding's own remediation paragraph intact rather than writing new remediation advice. Never add a finding, adjust a severity, or embellish evidence beyond what `report.md` already states -- the report renders only verified engagement data, and anything added on top of it is no longer something Boundhound actually confirmed.

## Scope & safety
Everything `report.md` describes has already passed the scope guard during recon, enum, exploit, and re-verification -- the report is not a place to add speculative findings against targets that were never actually tested in scope. Treat `report.md` as read-only output: if something in it looks wrong, the fix is upstream (re-run `/verify`, check `findings.json`, or check `scope.yaml`), not a manual edit to the rendered file.

## Checklist
- Confirm `/verify` has already produced `findings.json` before running `/report`.
- If `bh-report` fails closed, fix `scope.yaml` first rather than writing a report by hand.
- Quote severity, evidence, and remediation directly from `report.md` in the submission.
- Never alter `report.md` or add findings/evidence beyond what it already contains.
- Split per-finding sections cleanly when a program wants individual submissions instead of one combined report.
