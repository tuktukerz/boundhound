---
name: exposed-git
description: "Exposed git is a `.git` directory left reachable under a web root after deployment, which lets anyone who finds it read the full commit history, past file versions, and commit metadata for the application -- including credentials or internal detail that were removed from the current codebase but still exist in an earlier commit. Use this skill against any target whose deployment process copies a working repository directly into a served directory instead of exporting only the built application. Triggers: 'exposed git directory', 'git repository disclosure', '.git folder exposed', 'source control leak', 'git history exposure'."
version: 1.0.0
phase: ["enum"]
category: ["info-disclosure"]
tags: ["exposed-git", "version-control", "ffuf", "nuclei", "web"]
---

# Exposed Git

## What it is
An exposed `.git` directory is a deployment mistake with an unusually large blast radius: a working git repository -- not just the current files, but its entire commit history -- copied straight into a directory the web server serves. Whatever was ever committed is retrievable, even content that was deleted or rewritten in a later commit, since git keeps prior blobs around by design. A credential added and then "fixed" in a follow-up commit is still sitting in history, fully reachable by anyone who can enumerate the repository's object files.

## Where it shows up
It happens when a deployment process is a raw copy or checkout of a development repository into the web root instead of a build step that only exports the finished application. The tell is `.git/HEAD`, `.git/config`, or `.git/logs/HEAD` resolving directly under the site's URL -- any of which confirms a live repository sitting where only application files should be.

## How Boundhound approaches it
During `/enum`, ffuf (through `bh-exec`) checks well-known git-internal paths -- `.git/HEAD`, `.git/config`, and similar -- directly against discovered hosts, and nuclei's git-exposure templates (also through `bh-exec`) flag the same condition where a matching template exists. Confirmation is intentionally minimal: reading `.git/HEAD` or `.git/config` is enough to prove a live repository is exposed. Boundhound does not reconstruct or clone the full repository history from an exposed `.git` directory -- that would mean pulling down source and commit data well beyond what's needed to demonstrate the exposure.

## Scope & safety
Only hosts already listed in `scope.yaml` are probed, through `bh-exec`'s deny-by-default enforcement. Proof-of-exposure stops at reading one or two internal git files that establish the repository is live and reachable; it never extends to walking the object store to rebuild history or extract file contents, which stays out of scope for a non-destructive confirmation check.

## Remediation
Never deploy by copying or checking out a working repository into a web-served directory -- build and export only the finished application into the deployment target. Where a `.git` directory is discovered exposed, treat every credential and internal detail ever committed to that repository as compromised and rotate accordingly, since history cannot be selectively un-exposed after the fact.
