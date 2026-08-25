---
name: race-condition
description: "A business-logic race condition happens when an application checks a constraint -- a coupon's single-use flag, a wallet balance, a limited-stock counter -- and then acts on it in a separate step, without making the check-then-act sequence atomic; sending two or more requests at nearly the same instant can win that gap twice, redeeming a one-time coupon multiple times or withdrawing more than a balance allows. Use this skill when an endpoint enforces a 'use once' or 'do not exceed N' rule but nothing suggests the underlying operation is atomic. Triggers: 'race condition', 'toctou', 'double redemption', 'double spend', 'concurrent request abuse'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["business-logic"]
tags: ["race-condition", "business-logic", "concurrency", "toctou"]
---

# Race Condition (Business Logic)

## What it is
A business-logic race condition is a time-of-check-to-time-of-use gap: the server reads some state (has this coupon been used, is there stock left, is the balance sufficient), decides the request is allowed, and only afterward writes the updated state. If that read-decide-write sequence is not atomic, two requests arriving close enough together can both pass the check before either write lands, and both get treated as valid. The result is a coupon redeemed twice, a gift card debited past zero, or a limited-quantity item sold to more buyers than existed. This is a logic and timing flaw in the application's own request handling, not a memory-safety or protocol bug.

## Where it shows up
Any endpoint that enforces a "use once" or "do not exceed N" rule by checking then acting is a candidate: coupon and promo-code redemption, gift-card or wallet balance debits, withdrawal and transfer endpoints, flash-sale or limited-inventory purchases, "claim this reward" buttons, and vote-once endpoints. The tell is a constraint that clearly exists in the product ("each code redeems once") with no visible sign the operation is backed by a database transaction, row lock, or atomic decrement.

## How Boundhound approaches it
Business-logic races depend entirely on the application's own internal sequencing, so there is no bounded scanner for this -- Boundhound does not claim one. The safe path has two steps. First, `/enum` and recon (ffuf and endpoint mapping, through `bh-exec`) identify the candidate endpoint and confirm the constraint it is supposed to enforce. Second, the operator drives a small, controlled test through `/burp`: a fixed, small number of near-simultaneous requests (typically two to five) against the same endpoint, checking whether more than one succeeded when the business rule says only one should have. This is a bounded, in-scope concurrency probe, not a flood or denial-of-service attempt -- Boundhound's safety layer caps request rates and refuses any DoS-shaped burst, so the test only ever sends the minimum number of requests needed to observe whether the race exists.

## Scope & safety
The target endpoint must already be listed in `scope.yaml`; the Burp MCP guard denies by default and blocks anything outside that scope before a request is sent. Testing uses only sandbox or test-provisioned coupons, balances, and accounts belonging to the engagement -- the objective is to observe that two concurrent requests both succeeded, not to actually walk away with a duplicated reward, a real balance drained, or fraudulently obtained stock.

## Remediation
Make the check-then-act sequence atomic: use database transactions with row-level locking, atomic decrement/compare-and-swap operations, or unique constraints that reject a second redemption at the storage layer instead of in application code. Idempotency keys on state-changing requests and serializing critical sections around shared counters close the gap that application-level checks alone cannot.
