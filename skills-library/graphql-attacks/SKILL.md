---
name: graphql-attacks
description: "GraphQL attacks target the flexibility of a single GraphQL endpoint and its query language -- introspection revealing the entire schema, deeply nested or batched queries forcing disproportionate server work, and field-level authorization gaps that a REST API's per-endpoint checks would normally catch. Use this skill when a target exposes a single endpoint (typically `/graphql`) accepting POST queries rather than many fixed REST routes. Triggers: 'graphql', 'graphql introspection', 'graphql injection', 'nested query attack', 'graphql batching attack'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["api"]
tags: ["graphql", "introspection", "api", "query-abuse", "authorization"]
---

# GraphQL Attacks

## What it is
GraphQL exposes a single endpoint that accepts a query language describing exactly what data the client wants, instead of the many fixed endpoints a REST API would use. That flexibility creates its own attack surface: an introspection query can reveal the entire schema -- every type, field, query, and mutation the server defines, including ones no client currently calls; deeply nested, aliased, or batched queries can force the server to do disproportionate work for a single request; and because authorization in GraphQL is often applied inside individual resolvers rather than per endpoint, a field-level check can be missed even when the surrounding query looks unremarkable.

## Where it shows up
A single POST endpoint, usually `/graphql`, accepting a JSON body with a `query` field is the signature. Whether introspection is enabled -- a query requesting `__schema` or `__type` succeeding -- is the first thing worth checking, since it turns the entire schema into a map of every field and mutation available, including ones not otherwise reachable from the application's own interface. Deeply nested queries that traverse a type's own relationships recursively, and batched arrays of queries sent in one request, are the next things worth probing.

## How Boundhound approaches it
`/enum`'s recon and nuclei templates (through `bh-exec`) can flag a subset of exposed GraphQL endpoints and known misconfigurations -- such as introspection left enabled in production -- where a matching template exists. From there, this is manual, operator-directed work through `/burp`: sending an introspection query to pull the schema, walking that schema for sensitive types and mutations, and testing individual fields or mutations for a missing authorization check by comparing responses across accounts of different privilege -- all within the scope the Burp MCP guard enforces on every request. Boundhound does not run an automated GraphQL fuzzer or query-generation tool against a live schema on its own; there is no bounded tool in this system for that.

## Scope & safety
Every GraphQL endpoint queried must resolve to a target already in `scope.yaml`; the Burp MCP guard denies by default and blocks a request to any host outside scope before it is sent. Testing for excess resource consumption (deep nesting, large batches) is capped to the minimum needed to demonstrate the issue exists -- Boundhound does not send queries built to actually exhaust server resources or degrade availability.

## Remediation
Disable introspection in production, or restrict it to authenticated internal use only. Enforce authorization inside every resolver that returns sensitive data or performs a mutation, not just at the endpoint level, and apply query-depth limits, complexity scoring, or batch-size limits so a single request cannot do disproportionate work.
