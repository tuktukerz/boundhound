---
name: lfi
description: "Local file inclusion happens when an application dynamically includes or executes a file based on user-controlled input, and that input can be manipulated to point at a file already present on the server rather than the one the application intended -- turning a template or module-loading feature into a way to read, and sometimes execute, arbitrary local files. Use this skill when a parameter selects a template, module, or page fragment by name and that name is used directly in an include-style call. Triggers: 'local file inclusion', 'lfi', 'file inclusion vulnerability', 'log poisoning', 'template parameter inclusion'."
version: 1.0.0
phase: ["enum", "exploit"]
category: ["web-access-control"]
tags: ["lfi", "file-inclusion", "local-file-inclusion", "web"]
---

# Local File Inclusion

## What it is
LFI is a step beyond path traversal: instead of merely reading a file's contents through a display function, user input controls which file a scripting language includes and executes as code, or in some runtimes decodes or filters. That distinction matters because a successful LFI can move from information disclosure to code execution if an attacker can influence the contents of an included file -- for example through a log file that reflects request data, or an uploaded file whose name or extension the application will later include.

## Where it shows up
Parameters that select a template, language pack, or module by name in frameworks that build an include path from that name; multi-language sites mapping a language code to a language file; and modular or plugin systems that load a component by an ID or name supplied in the request. Any traversal sequence or scheme-style prefix that changes behavior on such a parameter is the signal.

## How Boundhound approaches it
`/enum` runs ffuf (through `bh-exec`) against candidate include-style parameters using targeted wordlists, and nuclei's local-file-inclusion templates flag known vulnerable patterns where a matching template exists. Confirming that an included file is actually being interpreted rather than just read is a manual step through `/burp`: request a known, harmless local file through the suspected parameter and confirm its contents appear in the response. Boundhound does not attempt to chain a confirmed LFI into log or session poisoning or code execution on its own -- that step, if pursued at all, is an explicit, manual, engagement-scoped decision made through `/burp`, not an automated action.

## Scope & safety
Testing stays within hosts already listed in `scope.yaml`; requests to anything else are refused before they are sent. Verification reads a single known file just far enough to prove the inclusion is real -- Boundhound does not pursue code execution or broad file harvesting as part of confirming an LFI finding.

## Remediation
Avoid building include paths from user input; where a dynamic include is unavoidable, resolve against a fixed allow-list of valid file names rather than accepting a path fragment directly. Disable dangerous include-time behaviors, such as remote stream wrappers, at the language or runtime configuration level as defense in depth.
