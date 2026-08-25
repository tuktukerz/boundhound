---
name: api-key-leakage
description: "API key leakage is the exposure of a secret credential -- an API key, access token, or service credential -- in a place an outside party can read it: client-side JavaScript, a public repository, a mobile app binary, a response body, or a misconfigured storage bucket. Use this skill when a target's client-side code, documentation, or public-facing assets might embed a live credential rather than only a public identifier. Triggers: 'api key leakage', 'exposed api key', 'hardcoded credential', 'leaked access token', 'secret in client code'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["api"]
tags: ["api-key", "secrets-exposure", "leakage", "recon"]
---

# API Key Leakage

## What it is
API key leakage is the exposure of a credential meant to stay server-side or otherwise controlled, in a location an outside party can read: bundled JavaScript shipped to every browser, a mobile app's decompiled binary, a public repository's commit history, a response body that echoes back more than it should, or a storage bucket left without access control. Unlike most flaws in this category, the issue isn't in an API's logic -- it's in where a secret ended up, and what it is still valid to do once found.

## Where it shows up
Client-side JavaScript bundles (key-shaped strings and common SDK-initialization patterns), mobile app binaries, `.env`-style files or configuration left reachable at a predictable path, error messages or debug endpoints that echo configuration back, and source-control history where a key was committed and later "removed" without being rotated. A leaked key's actual impact depends entirely on its scope and permissions -- a public, rate-limited, read-only key is a very different finding from a key that can write data or incur cost.

## How Boundhound approaches it
`/enum`'s nuclei templates (through `bh-exec`) can flag a subset of known key-shaped secret patterns in reachable responses and exposed configuration paths where a matching template exists, and forced-browsing-style ffuf runs (through `bh-exec`) surface predictable configuration or backup paths that might carry a credential. Searching public source history and repositories for committed secrets is a separate concern, covered by this library's recon-osint category (its github-recon playbook) rather than duplicated here. Once a candidate key is found, confirming whether it is live and what it authorizes is a manual, scoped check through `/burp` -- never a broad automated sweep of everything the key might unlock.

## Scope & safety
Every path or endpoint probed must already be in `scope.yaml`; `bh-exec` and the Burp MCP guard both refuse to dispatch against a target outside scope. Confirming a found key is live uses the minimum possible call -- a read-only, non-destructive request that proves validity -- never the full range of what the key permits, and never against a third-party service the key belongs to but that falls outside the engagement's own scope.

## Remediation
Never ship a secret-scoped API key to client-side code, a mobile binary, or a public repository -- keep it server-side, and use a short-lived, narrowly-scoped token for anything the client legitimately needs. Rotate any key that was ever exposed, even briefly, since removing it from a later commit does not invalidate a key that was already live in history.
