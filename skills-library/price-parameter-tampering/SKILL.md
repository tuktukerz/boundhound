---
name: price-parameter-tampering
description: "Price parameter tampering happens when a checkout or cart endpoint accepts a price, subtotal, discount amount, or currency-conversion value from the client instead of recomputing it from authoritative catalog data on the server, letting an attacker modify that value in transit to pay less than the real price or apply a discount that was never actually granted. Use this skill when a hidden field, JSON body field, or query parameter carries a monetary amount and the server's response appears to trust it rather than recalculate it. Triggers: 'price tampering', 'price manipulation', 'checkout price bypass', 'discount parameter tampering', 'client-side price trust'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["business-logic"]
tags: ["price-tampering", "business-logic", "checkout", "e-commerce"]
---

# Price Parameter Tampering

## What it is
Price parameter tampering is a trust failure: the server lets the client supply or echo back a value that represents money -- unit price, subtotal, total, discount amount, or a currency-conversion rate -- and then uses that value at checkout instead of recomputing it from the server's own pricing data. Because the field only needs to be intercepted and changed before the request is sent, this is one of the more direct ways a broken trust boundary translates straight into financial loss, rather than data exposure.

## Where it shows up
Cart and checkout endpoints where price, subtotal, discount, or a currency multiplier appears as a hidden form field, a JSON body property, or a query parameter are the primary targets; coupon-application endpoints that accept a discount percentage or fixed amount directly, rather than a code the server looks up and validates itself, are a close variant. The signal to look for is a server response that reflects an altered monetary value back unchanged, or a final total that moves when the parameter is changed, without any server-side recalculation from catalog data appearing to happen.

## How Boundhound approaches it
This is a trust-boundary and business-logic question specific to how a given checkout is built, so there is no bounded scanner for it. `/enum` and recon (ffuf and endpoint mapping, through `bh-exec`) locate the checkout and cart endpoints and identify which parameters look like price, discount, or amount fields. The operator then tests it through `/burp`: intercept the request, tamper with the price or discount field, and resubmit to see whether the server accepts the altered value into its calculated total or independently recomputes it from authoritative pricing data. Every request stays inside scope and denied by default outside it.

## Scope & safety
Testing must stay on targets and products already listed in `scope.yaml`. The check is non-destructive: confirm the flaw by observing the server accept a tampered value in its response or calculated total, then stop -- do not carry a tampered order through to real payment capture, fulfillment, or delivery. Use sandbox or test accounts and test products wherever the engagement provides them.

## Remediation
Never trust a client-supplied price, subtotal, discount, or conversion-rate field. Recompute every monetary value server-side from the authoritative catalog and pricing rules at each step of checkout, including final payment capture, and reject or flag a request whose client-supplied amount disagrees with the server's own calculation.
