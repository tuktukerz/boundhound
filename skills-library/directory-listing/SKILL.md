---
name: directory-listing
description: "Directory listing is a web server auto-generating and returning a full index of a directory's contents when no default index file is present, revealing every file in that directory -- including ones with no direct link from the application -- instead of the intended page or a not-found response. Use this skill when a discovered path resolves to a generated file listing rather than application content. Triggers: 'directory listing enabled', 'directory indexing', 'index of exposed', 'auto-generated file listing', 'browsable directory'."
version: 1.0.0
phase: ["enum"]
category: ["info-disclosure"]
tags: ["directory-listing", "content-discovery", "ffuf", "httpx", "web"]
---

# Directory Listing

## What it is
Directory listing is a web server feature, not a bug in the application running on it: when a requested directory has no default index file to serve, some server configurations fall back to generating and returning a plain listing of every file and subdirectory it contains, rather than a not-found or forbidden response. That default is harmless on a directory holding nothing but intended public assets, and a direct information leak on any directory holding configuration files, backups, logs, or anything else that was never meant to be individually linked -- listing turns "not linked" into "listed by name" for every file inside.

## Where it shows up
Any directory without an index file where the server hasn't been explicitly configured to forbid listing -- upload directories, asset folders, and old or half-migrated paths are the most common places it survives unnoticed, since a properly maintained application directory almost always has an index file to mask the setting either way. The signal is a response page titled something like "Index of /path/" with a plain table of file names, sizes, and modification dates instead of rendered application content.

## How Boundhound approaches it
During `/enum`, ffuf (through `bh-exec`) enumerates candidate directories as part of its normal content-discovery pass, and httpx (also through `bh-exec`) inspects the response title and body of anything discovered to recognize the distinctive "index of" listing pattern. nuclei's directory-listing detection templates (through `bh-exec`) independently flag the same condition where a matching template exists. Where a listing is found, Boundhound reads the file names it reveals to judge whether anything sensitive is named there -- it does not need to fetch every listed file to establish that the listing itself is a finding.

## Scope & safety
Only hosts already listed in `scope.yaml` are enumerated, and `bh-exec` enforces that boundary deny-by-default along with request-rate limits for the engagement. A directory listing is confirmed by the listing response itself; following up on an individual listed file is limited to what's needed to judge severity, not a bulk download of everything the directory contains.

## Remediation
Disable directory-listing (auto-indexing) at the web server configuration level for any directory that doesn't specifically need it, and place an index file in directories where the setting can't be disabled outright. Treat any directory that shows meaningful file names once listed -- configuration, backups, logs -- as needing to be moved outside the web root entirely, since disabling listing alone doesn't stop a file from being requested directly if its name is guessed.
