---
name: bola-idor-api
description: "Broken object level authorization on an API happens when an endpoint accepts an object identifier -- in the path, query string, or body, or as a GraphQL argument -- and returns or modifies that object without verifying the requesting caller actually owns or is entitled to it; it is the same underlying flaw as IDOR, manifesting through API routes and mobile-app backends rather than a browser-rendered page. Use this skill when an API endpoint takes an ID, UUID, or key that maps to a specific record and no ownership check is obviously enforced. Triggers: 'bola', 'broken object level authorization', 'api idor', 'object level authorization api', 'api object ownership bypass'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["api"]
tags: ["bola", "idor", "api", "authorization", "object-reference"]
---

# Broken Object Level Authorization (API)

## What it is
This is the API-surface form of insecure direct object reference: an endpoint accepts an object identifier -- a resource ID in a URL path segment, a key in a JSON body, or an argument to a GraphQL field or mutation -- and the server resolves and returns (or modifies) that object without independently checking that the authenticated caller is entitled to it. It is grouped separately from the general web `idor` playbook because API surfaces raise it in their own way: identifiers embedded in path segments rather than query strings, object references passed as typed GraphQL arguments, and mobile or third-party API clients that never expose the parameter tampering as visibly as a browser address bar would.

## Where it shows up
Any API route shaped like `/api/v1/resource/{id}` or `/api/orders/{orderId}/items`, any GraphQL field or mutation that takes an object ID as an argument, and any endpoint that returns a list of a caller's own objects -- which then hands back the exact identifiers worth testing against a different session -- are candidates. Numeric, sequential IDs are the easiest to enumerate, but UUIDs are still worth testing if they can be harvested from another response in the same API.

## How Boundhound approaches it
Like `idor`, this is an authorization and logic flaw with no single bounded tool that detects or exploits it end to end. The safe workflow follows the same two-step pattern: `/enum` uses ffuf and recon output (through `bh-exec`) to enumerate the API's endpoints and identify which routes and GraphQL fields carry an object identifier, building the candidate surface. Verification is manual and operator-directed through `/burp`: using two accounts of different privilege (or two distinct tenants), request the same object identifier from each session and compare the responses, entirely within the scope the Burp MCP guard enforces. Boundhound never automates swapping identifiers across accounts on its own.

## Scope & safety
Every object and endpoint probed must resolve to a target already in `scope.yaml`; the Burp MCP guard denies by default and blocks any request outside that scope before it is sent. Verification uses only accounts and objects belonging to the engagement's own test setup, and confirms access with the minimum request needed to prove the gap -- Boundhound never reaches a real, unrelated user's live data outside the provisioned test accounts.

## Remediation
Enforce object-level authorization inside the resolver or handler for every route and GraphQL field that accepts an identifier -- verify the authenticated caller owns or is entitled to that specific object on every request, regardless of how the identifier reached the server. Prefer scoping data-access queries to the caller's own tenant or account at the data layer, so a missing check fails closed instead of falling through to a global lookup.
