---
name: rest-api-testing
description: "REST API testing is the systematic exercise of an API's endpoints, HTTP methods, headers, and body parameters directly, independent of whatever front end normally drives it -- surfacing verbs, versions, and parameters a browser-driven crawl would never touch. Use this skill when a target exposes a documented or discovered REST-style API (JSON/XML request and response bodies, versioned `/api/v1/` style paths) rather than only server-rendered pages. Triggers: 'rest api testing', 'api endpoint testing', 'http method fuzzing', 'api version discrepancy', 'undocumented api parameter'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["api"]
tags: ["api", "rest", "endpoint-testing", "http-methods", "web"]
---

# REST API Testing

## What it is
REST API testing means probing an API's endpoints, HTTP methods, headers, and body parameters directly, rather than only exercising whatever a front end happens to send. An API is built to be machine-consumed, so it frequently accepts methods, parameters, and content types that no browser-driven client ever exercises -- an endpoint might answer PUT or DELETE even though the UI only ever sends POST, or accept an optional field the documentation never mentions. Testing the API surface on its own terms, not just through the UI, is what finds those gaps.

## Where it shows up
Any `/api/`, `/v1/`, `/v2/` style path, JSON or XML request/response bodies, and a host that returns a structured error body instead of an HTML error page are strong signals of a REST API. Worth checking on any discovered endpoint: which HTTP methods it actually answers beyond the one the front end uses, whether optional or undocumented parameters are silently accepted, and whether validation is consistent across near-identical routes -- an older API version (`/api/v1/users`) is a common place to find a check that a newer version (`/api/v2/users`) later added.

## How Boundhound approaches it
`/recon`'s httpx probing (through `bh-exec`) identifies which discovered hosts serve API traffic, and `/enum`'s ffuf run (through `bh-exec`) enumerates API paths, versioned route prefixes, and parameter names against wordlists tuned for API structure, while nuclei's exposure and misconfiguration templates flag a subset of known API issues where a matching template exists. Together this builds the map of the API surface -- routes, methods each one accepts, and expected content types. This playbook is intentionally broad: once the surface is mapped, individual candidate issues (an authorization gap, a mass-assignment field, a missing rate limit) are handed off to the other, more specific playbooks in this category rather than treated generically here.

## Scope & safety
Every endpoint and host probed must already be in `scope.yaml`; `bh-exec` refuses to dispatch ffuf, httpx, or nuclei against a target outside scope before a request is sent. Discovery and method/parameter enumeration are non-destructive by default -- state-changing verbs (POST, PUT, PATCH, DELETE) against a confirmed endpoint are only sent as part of a specific, scoped follow-up investigation, never as a blind sweep across every discovered route.

## Remediation
Apply the same authentication, authorization, input validation, and rate-limiting controls to every method and version of an endpoint, not just the ones a front end happens to call. Keep an accurate, current inventory of exposed routes and retire deprecated API versions rather than leaving an older, less-hardened path reachable indefinitely.
