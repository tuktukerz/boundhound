---
name: xxe
description: "XML external entity injection happens when an application parses attacker-supplied XML with external entity resolution enabled, letting an attacker define an entity that reads local files, reaches internal network resources, or exhausts server resources when the parser expands it. Use this skill when an endpoint accepts XML directly (SOAP APIs, file uploads that parse XML/Office/SVG formats, XML-based configuration import) and appears to parse it server-side. Triggers: 'xxe', 'xml external entity', 'xml injection', 'entity expansion', 'external entity attack'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["xxe", "xml", "web", "injection"]
---

# XML External Entity Injection

## What it is
XXE exploits an XML parser configured to resolve external entities declared in a document's DOCTYPE. A malicious document can declare an entity that points at a local file path or an internal URL; when the parser expands that entity during parsing, its content (or the response from the internal request) can leak back into the application's output, or the request itself can reach internal-only services.

## Where it shows up
Any endpoint that accepts raw XML is a candidate: SOAP-based APIs, file-upload features that parse XML-based formats (SVG, DOCX/XLSX which are ZIP-wrapped XML, RSS/Atom import), and configuration-import features. A response that changes when a DOCTYPE with an external entity is added to otherwise-valid XML is the signal to look for.

## How Boundhound approaches it
`/enum` runs nuclei (through `bh-exec`) against discovered endpoints, and its template set includes generic and CVE-specific XXE detection checks that can flag a matching case. Beyond detection, Boundhound does not currently have a bounded tool that actively exploits or extracts data via XXE -- that capability doesn't exist yet, and this skill does not pretend it does. The safe path for a flagged or suspected XXE candidate is manual verification through `/burp`: submit a minimal, non-destructive test entity (one that points at an obviously harmless, already-known-safe internal marker rather than a sensitive file) via Repeater and observe the response, staying within scope throughout. A dedicated bounded XXE tool can be added through `bh-exec` in a future phase.

## Scope & safety
Only in-scope endpoints from `scope.yaml` are tested. Verification probes must avoid reading sensitive files, reaching sensitive internal services, or triggering entity-expansion denial-of-service payloads -- the goal is a minimal, reversible proof of external-entity resolution, not extraction or disruption.

## Remediation
Disable external entity and DTD processing in the XML parser configuration (most modern parsers support this directly); where DTDs are genuinely required, use an allow-list-based, non-resolving parser mode. Prefer data formats that don't carry this risk (JSON) where XML isn't otherwise required.
