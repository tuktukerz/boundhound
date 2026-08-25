---
name: insufficient-quantity-validation
description: "Insufficient quantity validation happens when a quantity field -- items in a cart, units to transfer, a withdrawal count -- is not properly bounds-checked on the server, letting negative, zero, fractional, or excessively large values reach the pricing or inventory logic and produce results the application never intended, such as a negative total that credits the attacker or a purchase that exceeds real stock. Use this skill when a quantity parameter multiplies into a price or triggers an inventory or balance change without visible server-side range and type checks. Triggers: 'quantity validation', 'negative quantity', 'integer overflow quantity', 'stock manipulation', 'cart quantity abuse'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["business-logic"]
tags: ["quantity-validation", "business-logic", "input-validation", "e-commerce"]
---

# Insufficient Quantity Validation

## What it is
Insufficient quantity validation is a gap between what a quantity field is supposed to represent -- a positive whole number of units -- and what the server actually accepts. When a request's quantity value is not checked for type (must be an integer), range (must be positive and within a sane maximum), and availability (must not exceed real stock or balance) before it is used, an attacker can submit a value the business logic never anticipated. A negative quantity multiplied by a unit price can turn a purchase into a credit; a decimal quantity can dodge per-unit rounding; an unbounded large quantity can decrement inventory or a balance far past what should be possible.

## Where it shows up
Add-to-cart and update-cart endpoints, transfer or withdrawal amount fields, and bulk-order quantity APIs are the usual locations -- anywhere a quantity value is multiplied into a total price or used to decrement inventory or a balance. The signal is a quantity parameter that the server clearly uses in a calculation, with no evidence that negative, zero, non-integer, or very large values are rejected before that calculation happens.

## How Boundhound approaches it
Whether a given quantity field is validated is a property of the specific application's logic, so there is no bounded scanner that checks this end to end. `/enum` and recon (ffuf and endpoint mapping, through `bh-exec`) locate cart, order, and transfer endpoints and identify their quantity parameters. The operator then tests it through `/burp`, submitting boundary and invalid values -- negative, zero, a decimal, or an unusually large number -- for the quantity field to observe whether the server accepts them and whether the resulting total, inventory count, or balance behaves incorrectly. Requests stay scope-checked and denied by default outside the engagement's targets.

## Scope & safety
Only targets and products already in `scope.yaml` are tested. The check is non-destructive: the goal is confirming that the server accepted an invalid quantity or mis-calculated a total or inventory count from it, not completing a fraudulent order or actually draining real inventory or funds. Use sandbox or test-provisioned accounts, products, and balances wherever the engagement makes them available.

## Remediation
Validate every quantity value server-side on every request that uses it -- require an integer, require it to be positive, cap it at a sane maximum, and check it against real available stock or balance -- rather than relying on client-side form constraints. Recompute totals and inventory changes only from quantities that have passed this validation.
