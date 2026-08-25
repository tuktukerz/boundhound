---
name: command-injection
description: "OS command injection occurs when user input reaches a system shell call without proper isolation, letting an attacker append or substitute additional commands that the host executes with the application's privileges -- one of the highest-impact injection classes since it can lead directly to full host compromise. Use this skill when an application feature seems to shell out to the underlying OS (file conversion, ping/traceroute utilities, image processing, archive extraction) and accepts a parameter that could reach that call. Triggers: 'command injection', 'os command injection', 'shell injection', 'rce via command execution', 'code execution via shell'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["command-injection", "rce", "shell", "web", "injection"]
---

# OS Command Injection

## What it is
Command injection happens when user-controlled input is passed to a function that invokes the operating system's shell (or an equivalent process-spawning call) without separating data from command syntax, so shell metacharacters (semicolons, pipes, double ampersands, backticks, command substitution) let an attacker append their own commands to whatever the application intended to run.

## Where it shows up
Features that visibly wrap a system utility are the strongest candidates: network diagnostic tools exposed in a UI (ping, traceroute, DNS lookup), file-conversion or media-processing endpoints, archive/backup utilities, and any parameter that maps to a filename or hostname passed to a command-line tool server-side. Unusual delay after injecting a sleep-style shell command, or a response that changes when shell metacharacters are present, are common signals.

## How Boundhound approaches it
`/enum` runs nuclei (through `bh-exec`) against discovered endpoints, and its template set includes detections for several known command-injection issues and CVEs, so it can catch matching cases -- but nuclei's template coverage for this technique is signature-based, not a generic command-injection scanner, and Boundhound does not currently have a bounded tool that actively confirms or exploits generic OS command injection. When a parameter looks suspicious but no template matches, the safe path is manual verification through `/burp` within scope -- using non-destructive, read-only probes (for example, a harmless time-delay command) via Repeater to confirm execution without taking any action on the host. A dedicated bounded command-injection tool can be brought in through `bh-exec` in a future phase; until then, this skill does not claim automated exploitation capability it doesn't have.

## Scope & safety
Only in-scope hosts and parameters from `scope.yaml` are ever touched. Any probe used for manual verification must be non-destructive and read-only (e.g., a delay or an innocuous, side-effect-free command) -- never a command that writes, deletes, or exfiltrates, and never a reverse shell or persistence mechanism.

## Remediation
Avoid shelling out to the OS with user-controlled arguments; use language-native APIs (file, network, archive libraries) instead of a shell call. Where shelling out is unavoidable, use an execution API that passes arguments as an array (never a single interpolated string) and strictly allow-list acceptable input.
