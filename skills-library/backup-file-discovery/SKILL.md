---
name: backup-file-discovery
description: "Backup file discovery is finding copies of application files -- editor swap files, archive exports, or files renamed with a backup extension -- that were left reachable on a web server instead of being cleaned up after an edit or a manual deployment, often exposing full source code, credentials, or configuration that the live application file itself never reveals. Use this skill against any target where files might have been edited or deployed by hand rather than through a controlled pipeline. Triggers: 'backup file discovery', 'exposed .bak file', 'editor swap file exposure', 'archived source file leak', 'backup extension enumeration'."
version: 1.0.0
phase: ["enum"]
category: ["info-disclosure"]
tags: ["backup-files", "content-discovery", "ffuf", "nuclei", "web"]
---

# Backup File Discovery

## What it is
Backup file discovery is finding a copy of a file that was never meant to be requested directly, left behind on the web server by a habit that predates the application's actual deployment process -- an editor's automatic swap file, a manual copy made before an edit and never removed, or an archive export left in the web root after a deployment. Because the copy sits outside the application's normal routing, it usually isn't rendered or interpreted; it is served as a raw file, which means anything the original file contained -- including source code or embedded credentials -- comes back as plain text instead of processed output.

## Where it shows up
Files with a backup or editor-generated suffix appended to a known application filename -- a trailing tilde, `.bak`, `.old`, `.orig`, `.swp`, or a `.zip`/`.tar.gz` archive named after the site or a deployment date -- sitting alongside the live file they were copied from. It is most common on targets that show other signs of manual deployment: inconsistent file naming, directory listing enabled nearby, or a deployment process that clearly isn't automated.

## How Boundhound approaches it
During `/enum`, ffuf (through `bh-exec`) runs wordlist-driven content discovery seeded with known application filenames and a backup-extension list, requesting each candidate directly to check whether a backup copy resolves. nuclei's exposure templates (also through `bh-exec`) separately check for common, template-recognizable backup-file patterns. A discovered backup file is read only far enough to confirm what it is and that it contains meaningful application content -- not fully extracted or mined for every credential it might hold.

## Scope & safety
Content discovery only targets hosts already listed in `scope.yaml`, and `bh-exec` enforces deny-by-default request scoping and rate limits for the engagement. Confirming a backup file's exposure is a single read-only request; Boundhound reports that the file is reachable and what category of content it holds, rather than downloading and retaining its full contents.

## Remediation
Remove backup and editor-generated files from any web-accessible path as a standard part of the deployment process, and deploy through an automated pipeline that only ever places intended application files in the web root. Treat any backup or archive file discovered in production as an incident, since its mere presence usually means the deployment process itself needs fixing.
