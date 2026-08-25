---
name: retest-verification
description: "Using /verify to re-run a finding's SAME bounded check through bh-exec -- never a heavier scan -- to confirm a fix landed or that a finding still reproduces, and how a non-reproducing finding stays in findings.json flagged verified:false instead of being deleted. Use this skill when a program reports a fix, when re-confirming an old finding before writing it up, or when explaining why a re-check never escalates beyond the original tool. Triggers: 'retest verification', 'confirm a fix', 'verify finding still holds', 're-run bh-exec check', 'verified false', 'regression retest'."
version: 1.0.0
phase: ["verify"]
category: ["methodology"]
tags: ["verify", "methodology", "retest", "regression", "bh-exec"]
---

# Retest & Verification

## What it is
Retesting answers one narrow question about one specific finding: does it still hold, right now, exactly as originally reported. It is not a fresh scan and not an opportunity to look for new issues -- widening scope during a retest defeats the point, which is a clean before/after comparison against the same check.

## How Boundhound approaches it
`/verify` runs `bh-findings` to build the candidate list from whatever recon, enum, and exploit maps already exist, then for every unverified candidate it re-screens the target against the engagement's current in-scope/out-of-scope lists and re-runs that finding's own original bounded check through `bh-exec` into `output/verify/recheck/` -- the identical check that first produced the finding, never a heavier or different one, and never sqlmap again for a sqli finding that `/exploit` already confirmed. `bh-findings` then runs a second time to fold the recheck results back into `findings.json`: a `reproduced:true` result flips that finding's `confidence` to `confirmed` and `verified` to `true`. A finding that does not reproduce is never deleted -- it stays in `findings.json` flagged `verified:false`, so the report can still show that it was checked and did not hold at the time of the retest.

## Confirming a reported fix
When a program reports that a finding has been fixed, treat it exactly like any other retest: re-screen the target against current scope (a fix is sometimes bundled with a scope change), then re-run `/verify` so the same bounded check fires again. A fix that holds shows the finding flipping to non-reproducing (`verified:false` on the recheck) rather than disappearing -- Boundhound never deletes a finding just because a fix was claimed; the retest result is what settles it, not the claim.

## Scope & safety
A retest is bound by the same deny-by-default scope check as every other phase -- a target that has since moved out of scope is refused before the recheck runs, even if it was in scope when the finding was first produced. The recheck also never escalates the tool or its flags beyond what originally produced the finding; `bh-exec`'s bounded flag set (no destructive, DoS, dump, shell, or file-read/write flags) applies exactly the same on a retest as on the original run, so confirming a finding never becomes an opportunity to push further into the target.

## Checklist
- Re-run the exact same bounded check that produced the finding -- never substitute a stronger tool or wider flag set.
- Re-screen the target against current scope before retesting, since scope can change between the original finding and the retest.
- Never delete a non-reproducing finding; leave it as `verified:false` so the report reflects the retest honestly.
- Treat a program's "fixed" claim as something to retest, not something to accept and close without a recheck.
