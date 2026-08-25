---
name: idor
description: "Insecure direct object reference happens when an application exposes a reference to an internal object -- a database ID, filename, or key -- in a URL or parameter, and grants access to it without checking whether the requesting user is actually authorized to reach that specific object. Use this skill when a URL or parameter contains an ID, UUID, or filename that maps directly to a specific record, and changing that value might return another user's data or resource. Triggers: 'idor', 'insecure direct object reference', 'object reference tampering', 'user id manipulation', 'record enumeration'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-access-control"]
tags: ["idor", "access-control", "authorization", "object-reference", "web"]
---

# Insecure Direct Object Reference

## What it is
IDOR is an authorization failure, not an injection flaw: the application correctly authenticates the requester but fails to check whether that specific requester is allowed to access the specific object being referenced. An attacker who is otherwise a legitimate, logged-in user finds that swapping one ID for another (invoice number, profile ID, order ID, uploaded file name) returns data or performs an action outside their own account.

## Where it shows up
Any endpoint whose path or parameter carries a sequential, guessable, or otherwise enumerable identifier is a candidate: `/api/orders/1042`, `?user_id=884`, `/invoices/download?id=...`, `/documents/<uuid>`. Sequential integers are the easiest case, but even UUIDs are worth checking if they can be harvested from another response (list endpoints, notifications, shared links).

## How Boundhound approaches it
IDOR is a logic and authorization flaw, not something a single bounded tool can detect or exploit end to end -- Boundhound does not pretend otherwise. The safe path has two steps. First, `/enum` uses ffuf and recon output (through `bh-exec`) to enumerate the endpoints and object-identifier patterns a target exposes, building the candidate list of "this ID maps to that object" surfaces. Second, verification is manual and operator-directed through `/burp`: with two accounts of different privilege, request the same object ID from each session and compare responses, entirely within the Burp MCP guard's scope check. Boundhound never automates swapping arbitrary IDs across accounts on its own; the comparison is always driven from `/burp`.

## Scope & safety
Every object and endpoint probed must resolve to a target already listed in `scope.yaml`; the Burp MCP guard denies by default and blocks any request outside that scope before it is sent. Verification uses only accounts and objects that belong to the engagement -- Boundhound never reaches a real, unrelated user's live data outside the test accounts provisioned for the engagement, and confirms access with the minimum request needed to prove the gap.

## Remediation
Enforce object-level authorization checks on every request that resolves an identifier to a resource -- verify the authenticated user owns or is entitled to that specific object, not just that they are logged in. Prefer indirect, per-user reference maps or unguessable identifiers as defense in depth, but never as a substitute for the authorization check itself.
