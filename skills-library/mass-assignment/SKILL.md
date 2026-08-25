---
name: mass-assignment
description: "Mass assignment happens when an API endpoint binds an entire request body directly onto an internal object or database model without restricting which fields the client may set, letting an attacker include extra fields -- a role, an is_admin flag, a price, a balance -- that were never meant to be client-controlled. Use this skill when a create or update endpoint accepts a JSON body and the underlying object appears to carry fields wider than the documented, expected set. Triggers: 'mass assignment', 'over-posting', 'auto-binding vulnerability', 'unintended field update', 'privileged field injection'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["api"]
tags: ["mass-assignment", "api", "authorization", "object-binding"]
---

# Mass Assignment

## What it is
Mass assignment is a binding flaw: a framework convenience that maps request-body fields directly onto an object's properties or database columns is applied without an explicit allow-list, so any field present in the request that happens to match a property name gets set -- including fields the endpoint's documentation never mentions and the client was never supposed to control. The flaw isn't in any single field; it's in the missing boundary between "fields this endpoint accepts" and "fields this object happens to have."

## Where it shows up
Create and update endpoints that accept a JSON body mapped onto a rich internal object are the classic case: a user-profile update endpoint whose object also has a `role` or `is_admin` column, an order-creation endpoint whose object also carries a `price` or `discount` field, or a registration endpoint whose user object includes an `email_verified` or `account_tier` flag. The tell is a documented, narrow set of expected request fields sitting on top of a much wider internal object -- the gap between the two is the surface worth testing.

## How Boundhound approaches it
Mass assignment is a binding and authorization flaw with no single bounded tool that detects or exploits it end to end -- Boundhound is explicit about that rather than implying automated coverage. `/enum` uses ffuf and nuclei (through `bh-exec`) to map the API's endpoints, and where a response body or accompanying documentation exposes a wider object schema than the documented request fields, that mismatch surfaces as a candidate. Confirming an actual mass-assignment gap -- adding an undocumented field to a request body and observing whether it was silently applied -- is manual, operator-directed work through `/burp`, within the scope the Burp MCP guard enforces on every request.

## Scope & safety
Every endpoint tested must already be in `scope.yaml`; the Burp MCP guard denies by default and blocks a request to any host outside scope before it is sent. Verification adds one candidate field at a time using the engagement's own test account and checks the resulting object state -- Boundhound confirms the field was accepted, it does not use a confirmed gap to escalate privilege or modify data beyond what is needed to prove the issue.

## Remediation
Bind requests through an explicit allow-list of fields per endpoint rather than mapping the entire request body onto an internal object; deny by default on any field not explicitly expected. Keep privileged fields -- role, price, verification flags, ownership -- out of any object that is directly bound from client input, and set them only through dedicated, separately-authorized code paths.
