---
name: xss-stored
description: "Stored cross-site scripting occurs when attacker-supplied input is saved server-side (a comment, profile field, support ticket, or file name) and later rendered to other users without proper encoding, so the payload executes in every victim's browser each time the stored content is displayed. Use this skill when a field's content persists across requests/sessions and is later rendered as HTML -- comments, user profiles, message threads, and admin-facing content review pages are typical candidates. Triggers: 'stored xss', 'persistent xss', 'cross-site scripting', 'xss', 'persistent script injection'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["xss", "stored", "persistent", "web", "injection"]
---

# Stored Cross-Site Scripting

## What it is
Stored XSS is the persistent counterpart to reflected XSS: the injected script is saved by the application (in a database, file, or cache) and rendered back to potentially many users on a later, unrelated request. That makes it more dangerous than reflected XSS -- no social engineering is required to deliver the payload, since visiting the page that displays the stored content is enough to trigger it.

## Where it shows up
User-generated content that other users or administrators later view is the target: comments, reviews, profile bios, support-ticket messages, file names/metadata, and chat or messaging features. Any field that accepts free text and is rendered as HTML elsewhere in the application deserves testing, especially content that surfaces on an admin or moderation dashboard, since that raises the impact of a successful payload.

## How Boundhound approaches it
`/enum` runs nuclei's XSS detection templates (through `bh-exec`) against known input points, and ffuf (through `bh-exec`, also under `/enum`) helps surface additional endpoints and parameters that accept and later render user content. Because confirming persistence means submitting a payload and then checking a second, separate rendering context, manual verification happens through `/burp`: submit a marker payload with Repeater, then load the page that renders the stored content and confirm execution. Every `/burp` call passes through the Burp MCP scope guard, deny-by-default like `bh-exec`.

## Scope & safety
Submission targets must be inside `scope.yaml`; nothing outside scope is touched. Because stored payloads persist, Boundhound uses inert, clearly-marked, non-destructive markers (harmless alert/console-log calls or a unique tagged string) and removes or reports them for cleanup rather than leaving persistent script content behind -- proof-of-vulnerability only, never a lasting foothold.

## Remediation
Encode output at render time based on context (HTML, attribute, JS, URL), regardless of how the input was stored. Combine this with input validation on write and a strict Content-Security-Policy to limit the blast radius of any payload that slips through.
