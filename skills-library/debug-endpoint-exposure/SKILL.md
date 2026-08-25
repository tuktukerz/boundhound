---
name: debug-endpoint-exposure
description: "Debug endpoint exposure is a diagnostic route, health-check panel, or development console that was useful while building an application and was never disabled or access-restricted before it shipped, often revealing environment variables, internal routing, dependency versions, or an interactive shell far beyond what a production caller should ever reach. Use this skill against any target that might carry framework or application debug tooling left reachable from outside. Triggers: 'debug endpoint exposure', 'exposed admin panel', 'debug console reachable', 'diagnostic endpoint left enabled', 'development tooling in production'."
version: 1.0.0
phase: ["enum"]
category: ["info-disclosure"]
tags: ["debug-endpoints", "misconfiguration", "ffuf", "nuclei", "web"]
---

# Debug Endpoint Exposure

## What it is
A debug endpoint is functionality built for the development phase of an application's life -- a diagnostic route that dumps environment variables, a health-check panel that lists internal service dependencies, an interactive console meant for a developer's local machine -- that quietly survives into production because turning it off was never made part of the deployment checklist. Unlike a bug in application logic, this is intended functionality reaching an audience it was never designed for; the risk scales with how much internal detail, or how much interactive control, the endpoint happens to expose.

## Where it shows up
Predictable diagnostic paths -- status and health-check routes, framework-default debug or admin consoles, environment-dump endpoints -- that were reasonable to leave open in a development environment and were never revisited before going live. The tell is usually a response that looks nothing like the rest of the application: raw configuration output, an interactive prompt, or a listing of internal routes and dependencies that a normal user-facing page would never surface.

## How Boundhound approaches it
During `/enum`, ffuf (through `bh-exec`) runs wordlist-driven discovery against common debug, admin, and diagnostic path patterns, and nuclei's exposed-panel and misconfiguration templates (also through `bh-exec`) flag known, template-recognizable debug endpoints by their distinctive response signature. httpx (through `bh-exec`, `/recon` and `/enum`) confirms status code and page title for anything discovered, which is often enough on its own to distinguish a real debug endpoint from a normal 404. Where an endpoint appears interactive rather than purely informational, confirming what it actually allows is manual work through `/burp`, within scope -- limited to observing what the endpoint reveals or permits, not exercising every capability it offers.

## Scope & safety
Only hosts already listed in `scope.yaml` are probed, and `bh-exec` refuses anything outside scope before a request is sent. Confirmation stops at proving the endpoint is reachable and characterizing what it exposes; Boundhound does not use a discovered debug console to make configuration changes, run destructive commands, or pivot further into the environment.

## Remediation
Disable or remove debug, diagnostic, and administrative tooling before deploying to production, and where a health-check or diagnostic route is genuinely needed there, put it behind authentication and restrict it to internal network access rather than the public internet. Make disabling debug tooling an explicit, checked step in the deployment process rather than an assumption that it happens automatically.
