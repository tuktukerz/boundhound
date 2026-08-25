---
name: nosql-injection
description: "NoSQL injection happens when user input is passed into a NoSQL database query (MongoDB, CouchDB, and similar) as structured data or operators rather than as a plain scalar value, letting an attacker manipulate query logic -- for example, submitting a JSON object with a not-equal or greater-than operator where a plain string was expected -- to bypass authentication or extract unintended data. Use this skill when a target's backend appears to be a document/NoSQL database and inputs are accepted as JSON or form-encoded structures rather than simple strings. Triggers: 'nosql injection', 'mongodb injection', 'operator injection', 'nosql auth bypass', 'json query injection'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["nosql-injection", "mongodb", "web", "injection"]
---

# NoSQL Injection

## What it is
NoSQL injection is conceptually similar to SQL injection but exploits query-object structure rather than string syntax: many NoSQL drivers let a caller submit query operators as part of the request payload, and if the application passes that structure straight into a query without validating its shape, the attacker can change the query's meaning entirely -- for example, turning a password-equality check into an always-true comparison.

## Where it shows up
Login and search forms backed by a document database are the primary target, especially where the application accepts JSON bodies and doesn't strictly type-check each field. Submitting a JSON object carrying a query operator in place of an expected string value, and observing a login succeed or a filter return unexpected results, is the classic confirmation.

## How Boundhound approaches it
Boundhound does not currently have a bounded tool that automatically detects or exploits NoSQL injection -- nuclei's template set has little reliable generic coverage for this technique, since it depends heavily on how a specific backend and driver parse query operators, so `/enum` cannot be relied on to flag it automatically. This skill says so plainly rather than implying a scan will catch it. The safe path today is manual verification through `/burp`: within scope, replace a string parameter's JSON value with an operator-based object via Repeater and observe whether the application's query logic changes. A dedicated bounded NoSQL-injection tool can be brought in through `bh-exec` in a future phase.

## Scope & safety
Testing stays limited to endpoints and parameters already in `scope.yaml`. Verification probes are limited to non-destructive read/auth-check operations -- proving that an operator-based payload changes query behavior, not using it to extract, modify, or delete data.

## Remediation
Strictly validate the type and shape of every field before it reaches a database query -- reject any field where a scalar (string, number) is expected but an object or operator is received. Where the driver supports it, use parameterized/prepared query builders instead of passing raw request structures into query construction.
