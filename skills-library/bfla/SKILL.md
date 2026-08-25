---
name: bfla
description: "Broken function level authorization happens when an API exposes an administrative or privileged operation -- an endpoint or mutation a regular user's client never calls -- without checking server-side that the caller's role actually permits that function, relying instead on the client simply not offering the option in its interface. Use this skill when an API appears to serve separate privilege tiers (user vs admin, tenant vs superadmin) from the same backend and a privileged-sounding operation exists. Triggers: 'bfla', 'broken function level authorization', 'function level authorization api', 'privileged api function', 'admin api endpoint no role check'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["api"]
tags: ["bfla", "api", "authorization", "function-level-access", "privilege"]
---

# Broken Function Level Authorization

## What it is
BFLA is an authorization failure at the level of which *operation* a caller may invoke, rather than which *object* they may reach. An API often serves multiple roles from the same backend -- a regular user's app and an admin console both call the same API -- and relies on the client only exposing privileged calls (delete a user, change a role, issue a refund, export all records) to admin sessions. If the server never independently verifies the caller's role before executing that function, any authenticated caller who knows or discovers the route can invoke it directly.

## Where it shows up
Administrative-sounding routes or mutations reachable from a non-admin session: `/api/admin/...` paths, bulk or export endpoints, role-change or user-management mutations, and any operation whose interface is hidden for non-admin users but whose underlying route was never separately access-controlled. Versioned or internal-sounding API paths discovered during enumeration but not linked from any visible interface are especially worth checking -- they were often built for internal tooling and had access control deferred on the assumption nobody outside would call them.

## How Boundhound approaches it
Like broken access control, BFLA is a logic and authorization category with no single bounded tool that detects or exploits it end to end. `/enum` uses ffuf (through `bh-exec`) against recon output to map the full set of routes and GraphQL operations an API exposes -- including ones no client interface links to -- and nuclei's exposure-related templates flag a subset of known misconfiguration patterns where a matching template exists. Confirming that a specific privileged function lacks the role check it should have is manual, through `/burp`: invoking the function directly from a lower-privilege or unauthenticated session and comparing the result against the expected restriction.

## Scope & safety
Endpoint discovery and verification both stay inside `scope.yaml`; the Burp MCP guard denies by default and refuses to send a request to a host outside scope. Verification calls the privileged function with the minimum input needed to observe whether the role check fires -- where the function is destructive or state-changing, Boundhound uses the engagement's own test data and confirms the gap without carrying out the underlying privileged action against real data.

## Remediation
Re-derive and check the caller's role or permission server-side for every function, using a trusted session or token, before executing it -- never rely on the client's interface being the only thing gating a privileged operation. Apply a centralized authorization layer per operation, not just per object, so a new privileged endpoint cannot ship without an explicit role check.
