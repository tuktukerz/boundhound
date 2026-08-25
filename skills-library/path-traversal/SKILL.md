---
name: path-traversal
description: "Path traversal, also called directory traversal, happens when an application accepts a file path or filename from user input and uses it to build a file-system path without properly restricting it to an intended directory, letting an attacker use sequences such as dot-dot-slash or an absolute path to reach files outside the directory the application meant to expose. Use this skill when a parameter, filename, or template argument looks like it is used to build a file-system path -- a document viewer, a download endpoint, a log viewer, or a theme or template selector. Triggers: 'path traversal', 'directory traversal', 'dot dot slash', 'traversal sequence', 'arbitrary file read via path'."
version: 1.0.0
phase: ["enum", "exploit"]
category: ["web-access-control"]
tags: ["path-traversal", "directory-traversal", "file-read", "web"]
---

# Path Traversal

## What it is
Path traversal exploits the gap between the file path the application intended to serve and the file path it actually resolves once user input is concatenated into it. Sequences that walk up the directory tree, encoded variants of those sequences, or absolute paths let the resolved path escape the intended directory and reach arbitrary files the web server process can read, and less commonly write.

## Where it shows up
Endpoints that take a filename, template name, language code, or document ID and use it to open a file: a `file` parameter, a `page` parameter, a `lang` parameter, static-asset or download handlers, and log or backup viewers. A parameter that clearly names a file, combined with any response difference when a traversal sequence is supplied, is the signal to check further.

## How Boundhound approaches it
During `/enum`, Boundhound runs ffuf (through `bh-exec`) with path-traversal-oriented wordlists against candidate parameters and endpoints to surface likely file-path handling, and nuclei's file-inclusion and path-traversal templates flag known vulnerable patterns where a matching template exists. Once a candidate parameter is identified, confirming an actual out-of-directory read is manual, through `/burp`: send a traversal payload targeting a harmless, known file and check the response for its contents, rather than automating a broad file-read sweep.

## Scope & safety
Every parameter and endpoint tested must already resolve to a target in `scope.yaml`; anything else is refused before a request is sent. Confirmation reads a single, non-sensitive, well-known file, such as a version marker, just far enough to prove the traversal works -- Boundhound does not use path traversal to trawl the file system for credentials or sensitive data.

## Remediation
Resolve the requested path, canonicalize it, and verify it still falls within the intended base directory before opening it -- reject the request if it does not, rather than trying to blocklist traversal sequences. Where possible, avoid passing user input into file-system paths at all: map user-facing identifiers to file paths through a fixed, server-side lookup table.
