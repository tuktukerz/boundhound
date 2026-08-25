---
name: swagger-openapi-recon
description: "Swagger/OpenAPI recon is locating and parsing a target's exposed API documentation or schema definition file -- a Swagger/OpenAPI JSON or YAML document, sometimes with a browsable UI -- to enumerate its entire documented endpoint, parameter, and schema surface without discovering it path by path. Use this skill when a target's API might publish, intentionally or by leftover misconfiguration, a machine-readable definition of its own surface. Triggers: 'swagger', 'openapi', 'api documentation exposure', 'swagger ui exposed', 'openapi spec discovery'."
version: 1.0.0
phase: ["recon", "enum"]
category: ["api"]
tags: ["swagger", "openapi", "api-recon", "documentation-exposure"]
---

# Swagger/OpenAPI Recon

## What it is
Many APIs publish a machine-readable definition of their own surface -- a Swagger or OpenAPI document listing every route, parameter, expected schema, and sometimes authentication requirement -- either intentionally for API consumers or left reachable by accident on a path the front end never links to. When this document is exposed, it collapses what would otherwise be slow, path-by-path enumeration into reading a single file: the target has effectively published its own attack-surface map.

## Where it shows up
Common, predictable paths carry this: `/swagger.json`, `/swagger-ui/`, `/openapi.json`, `/v1/api-docs`, `/api-docs`, and similar framework-default locations, along with any browsable, rendered API documentation page. Even when the interactive UI itself is gated behind authentication, the underlying JSON/YAML definition file it fetches is sometimes reachable directly and unauthenticated.

## How Boundhound approaches it
`/recon`'s httpx probing (through `bh-exec`) checks discovered hosts for the common documentation paths, `/enum`'s ffuf run (through `bh-exec`) extends that with a broader wordlist tuned to framework-default documentation and spec locations, and nuclei's exposure templates flag a subset of known documentation-exposure misconfigurations where a matching template exists. Once a definition file is found, Boundhound parses it to enumerate every documented route, parameter, and schema -- turning that list directly into the candidate surface that `rest-api-testing` and the other playbooks in this category work from, rather than re-discovering it manually one route at a time.

## Scope & safety
Every host probed for a documentation path must already be in `scope.yaml`; `bh-exec` refuses to dispatch httpx, ffuf, or nuclei against a target outside scope before a request is sent. Reading and parsing an exposed definition file is non-destructive -- it is a single GET against a static document, not an action against any of the endpoints the document describes.

## Remediation
Do not expose a Swagger/OpenAPI definition or its interactive UI in production unless the API is intentionally public; where it must be available, require authentication for both the rendered UI and the underlying spec file itself, not just the UI. Review a published spec for anything that should not be public before publishing it -- internal-only routes, example credentials, or infrastructure detail.
