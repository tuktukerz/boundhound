---
name: workflow-bypass
description: "A workflow bypass happens when a multi-step process -- checkout, onboarding, a verification flow, a multi-page application form -- assumes its steps happen in order but does not enforce that order on the server, letting a request for a later step succeed even though the earlier steps it depends on were never completed. Use this skill when a process has multiple stages and the server appears to track progress through a client-supplied step number, status field, or hidden parameter rather than server-side session state. Triggers: 'workflow bypass', 'step skipping', 'multi-step process bypass', 'business logic bypass', 'stage skip vulnerability'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["business-logic"]
tags: ["workflow-bypass", "business-logic", "multi-step", "state-machine"]
---

# Workflow Bypass

## What it is
Many applications implement a process as a sequence of steps: add items to a cart, enter shipping details, pay, confirm; or submit an application, verify identity, get approved. A workflow bypass exists when the server trusts that a request for a later step means the earlier steps already happened, instead of actually checking that they did. An attacker who requests a later-step endpoint directly, replays an earlier request out of order, or tampers with a step/status parameter can land in a state -- "order confirmed," "identity verified," "application approved" -- that should only be reachable after completing the prerequisites the workflow was designed to enforce.

## Where it shows up
Multi-page or multi-step forms and wizards, checkout flows that move through cart, shipping, payment, and confirmation, state-machine-backed processes such as loan or benefits applications, and any flow where progress is tracked by a client-visible field (a `step` number, a `status` string, a hidden form value) rather than something the server derives independently from what has actually been completed. The tell is a later-stage endpoint that responds successfully even when the requests for its prerequisite stages were skipped or sent out of order.

## How Boundhound approaches it
Understanding which sequence a workflow is supposed to enforce requires reasoning about the application's intended design, so there is no bounded tool for this -- Boundhound is explicit that this step is manual. `/enum` and recon (ffuf and endpoint mapping, through `bh-exec`) first build the full picture of the workflow's endpoints, mapping each stage to its request. From there, the operator drives testing through `/burp`: replaying a later-stage request without the earlier ones, resending requests out of sequence, or tampering with a step/status parameter, to see whether the server actually validates that the prerequisite stages completed or simply trusts whatever state it is told. Every request stays scope-checked and deny-by-default through the Burp MCP guard.

## Scope & safety
The workflow and its endpoints must already be in `scope.yaml`. Testing is non-destructive: the goal is confirming that a stage was reachable without its prerequisites, not carrying the bypass through to a completed transaction, a real approval, or a fraudulently placed order. Use test accounts and test data provisioned for the engagement throughout.

## Remediation
Track workflow progress server-side -- in the session or database, never in a value the client can set -- and validate on every request that the prerequisite stages actually completed before allowing the next one. Treat any client-supplied step, status, or stage parameter as a hint at most, never as authoritative.
