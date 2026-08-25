---
name: rfi
description: "Remote file inclusion is a variant of local file inclusion where the same unsafe include-style call accepts a fully qualified URL instead of a local path, letting an attacker point the include at a file they control on infrastructure outside the target -- turning file inclusion directly into remote code execution in languages or configurations that will fetch and execute a remote resource. Use this skill when an include-style parameter accepts what looks like a URL, or when a local-file-inclusion parameter is being tested for whether it also accepts a remote scheme. Triggers: 'remote file inclusion', 'rfi', 'remote code execution via include', 'url based inclusion', 'external file inclusion'."
version: 1.0.0
phase: ["enum", "exploit"]
category: ["web-access-control"]
tags: ["rfi", "file-inclusion", "remote-file-inclusion", "web"]
---

# Remote File Inclusion

## What it is
RFI exists where the same weakness that enables local file inclusion is combined with a runtime configuration that allows an include-style call to fetch a URL rather than only a local path. Where that combination holds, an attacker who can host content of their choosing on infrastructure they control can have the target fetch and execute it directly, which is a materially higher-impact outcome than local file inclusion's information-disclosure-first profile.

## Where it shows up
The same parameter families as local file inclusion -- template, module, or language-pack selectors used in an include-style call -- are the entry point; RFI is confirmed when the same parameter also accepts a value beginning with a URL scheme and the response indicates the remote resource was fetched.

## How Boundhound approaches it
`/enum` runs ffuf (through `bh-exec`) against candidate include-style parameters, and nuclei's remote-file-inclusion and related templates flag known vulnerable configurations where a matching template exists. Because proving RFI requires the target to fetch attacker-hosted content, verification through `/burp` uses only an already-in-scope, engagement-controlled listener or callback destination to confirm the outbound fetch happened -- Boundhound never points a candidate RFI parameter at an arbitrary third-party or production URL, and it does not progress a confirmed fetch into code execution automatically.

## Scope & safety
The include-style parameter under test, and any callback destination used to observe the fetch, must both be covered by `scope.yaml`; the Burp MCP guard refuses anything outside that scope before a request is sent. Verification stops at proving the remote fetch occurred -- Boundhound treats turning that fetch into code execution as a separate, explicit, manual decision within the engagement's rules, not an automated next step.

## Remediation
Disable remote-stream-style includes at the runtime or language configuration level; where a dynamic include is required, resolve strictly against a local allow-list of valid file names and never accept a URL as an include target. Keep this control at the platform level rather than relying only on application-level input validation.
