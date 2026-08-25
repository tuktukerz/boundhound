---
name: smb-enumeration
description: "SMB enumeration is inspecting a target's SMB/CIFS file-sharing service (typically TCP 445, sometimes 139) to learn its version and whether it exposes shares, host details, or protocol-level information beyond what a normal client needs, since a network file-sharing service left reachable and loosely configured can leak more about a target's internal structure than its web application ever would. Use this skill once a port scan has identified SMB as open on an in-scope host, to decide whether deeper SMB-specific investigation is warranted and safe. Triggers: 'smb enumeration', 'cifs recon', 'smb share discovery', 'windows file share exposure', 'smb port 445'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["infra-network"]
tags: ["smb", "cifs", "file-share", "nmap", "network"]
---

# SMB Enumeration

## What it is
SMB (Server Message Block, also called CIFS) is the protocol Windows hosts and many network-attached storage or backup appliances use to expose file shares over the network. Enumerating it means identifying the protocol version in use and, where access allows, what shares exist and whether any of them permit anonymous or guest browsing and reads. A share left open to unauthenticated listing can hand over internal file structure -- and sometimes actual sensitive files -- before a single valid credential is ever supplied.

## Where it shows up
Any host with TCP 445, or the older TCP 139, reachable from the network a scan runs from is a candidate. Recurring findings include Windows hosts accidentally reachable outside their intended network segment, storage or backup appliances that shipped with guest access enabled during initial setup and were never revisited, and legacy protocol versions still permitted where a modern, authenticated-only configuration should be the default.

## How Boundhound approaches it
During `/recon`, Boundhound's bounded nmap invocation (through `bh-exec`) includes SMB's ports in its fixed port set, so an open 445 or 139 is captured as part of the normal service map, and nmap's service/version probe on that port can identify the SMB implementation and version listening. Boundhound does not yet have a dedicated bounded tool for SMB-specific enumeration -- share listing, null-session checks, or protocol detail beyond what nmap's probe already surfaces -- so that deeper step is not run automatically today. When an in-scope host's SMB port is found open and worth a closer look, the safe path is either bringing a dedicated SMB enumeration tool into the system through `bh-exec`, subject to the same scope and safety review every bounded tool goes through before it can run, or performing the check by hand, strictly against the host already confirmed in `scope.yaml`.

## Scope & safety
The host exposing SMB must already be confirmed in `scope.yaml` before nmap's detection pass runs, let alone before any deeper enumeration is considered -- `bh-exec` refuses to dispatch against anything outside scope by default. Any SMB tool wired into Boundhound in the future would carry the same bounded, non-destructive posture as every existing tool: read-only listing and version checks, never credential attacks or writes to a share, and any interim manual check stays inside the same scope boundary.

## Remediation
Disable legacy SMB protocol versions and require authentication on every share; guest or anonymous access should never be enabled on a share holding anything sensitive. Firewall SMB ports away from any network segment that has no genuine need for file-sharing access, and audit share permissions on a schedule rather than assuming a configuration that was correct at setup stays that way.
