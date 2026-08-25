---
name: ftp-anonymous
description: "Anonymous FTP checking is testing whether a target's FTP service (TCP 21) still accepts the protocol's well-known \"anonymous\" login with no real credential, a decades-old convenience feature that plenty of FTP servers still ship with enabled and that -- left on for anything other than a deliberate public file drop -- lets anyone browse or pull whatever the anonymous account can reach. Use this skill once a port scan has identified FTP as open on an in-scope host, to decide whether a single, bounded anonymous-login check is worth performing. Triggers: 'ftp anonymous login', 'ftp anonymous access', 'ftp port 21', 'anonymous ftp', 'ftp misconfiguration'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["infra-network"]
tags: ["ftp", "anonymous-login", "file-transfer", "nmap", "network"]
---

# Anonymous FTP

## What it is
FTP's "anonymous" login is a standard, protocol-level feature dating back to when it was a common way to distribute files before the web existed: a client logs in with the literal username `anonymous` and any string (traditionally an email address) as the password, with no real credential required. Plenty of FTP daemons still ship with this enabled by default. The check is simply attempting that one well-known login and observing what, if anything, the anonymous account can browse or read.

## Where it shows up
Internal file servers, embedded update or firmware-distribution servers on network devices, and legacy infrastructure that has not been touched since it was first stood up are the recurring places this turns up. When it is intentional -- a genuine public file drop -- it is a non-issue; when it is a forgotten default on a server holding anything else, it hands over that content to anyone who tries the login.

## How Boundhound approaches it
During `/recon`, FTP's port sits in the fixed port set Boundhound's bounded nmap invocation (through `bh-exec`) checks, so an open TCP 21 is captured in the normal service map, and nmap's service/version probe can often read the server's banner directly. Boundhound has no dedicated bounded tool that performs the anonymous-login attempt and lists what it returns -- the login attempt itself is a single, well-documented, non-guessing action rather than anything resembling brute force, but it is still an active step Boundhound does not automate today. On a confirmed in-scope host, the safe path is a manual, operator-directed anonymous-login check, or a dedicated tool for it brought into the system through `bh-exec` with its own scope and safety review, exactly like every other bounded tool.

## Scope & safety
Only a host already confirmed in `scope.yaml` is checked, and the check is exactly one login attempt with the standard `anonymous` credential -- never a series of guesses, and never followed by anything beyond observing what the account can read. If anonymous access is confirmed and exposes content, that content is a finding to report, not something to download or exfiltrate further.

## Remediation
Disable anonymous FTP access unless it is a deliberate, reviewed public file drop, and even then restrict what the anonymous account can reach. Where plain FTP is still required at all, prefer a version that supports encryption and authentication over the unauthenticated legacy default, and review the setting periodically rather than assuming it was checked once and forgotten correctly.
