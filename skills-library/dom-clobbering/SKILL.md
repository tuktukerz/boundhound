---
name: dom-clobbering
description: "DOM clobbering happens when injected HTML elements with colliding id or name attributes get exposed as global variables or shadow object properties that a page's own script reads without validation, letting an attacker manipulate application logic through markup alone, without ever executing script. Use this skill when a sanitizer allows benign-looking tags through a stored-injection point and the page's script reads a global configuration value or callback without checking its type. Triggers: 'dom clobbering', 'html injection global shadowing', 'sanitizer bypass without script execution', 'named element global collision'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["dom-clobbering", "javascript", "client-side", "web"]
---

# DOM Clobbering

## What it is
DOM clobbering is a technique where an attacker injects HTML through a limited injection point that does not permit script execution -- typically a sanitizer that strips `<script>` but still allows other tags -- crafting elements whose `id` or `name` attributes collide with global variable names or property paths a page's own JavaScript expects to reference. Named HTML elements become accessible as global properties on `window`, and nested elements can shadow object properties, so a page's script can end up reading an attacker-controlled DOM node instead of the value or configuration object it intended. This alters application logic without any injected script ever running, which is exactly why sanitizers that only block `<script>` can still leave this door open.

## Where it shows up
Pages that pass through a sanitizer allowing benign-looking tags (`img`, `a`, `form`, a restricted `iframe`) while relying on unguarded global lookups in their own script -- reading `window.config`, a callback URL, or a flag variable without first checking that the value is the expected type. It is most relevant as an escalation path from a stored HTML-injection point a sanitizer has otherwise neutralized against direct script execution, turning what looks like a low-severity injection into logic manipulation or a stepping stone toward DOM-based cross-site scripting.

## How Boundhound approaches it
DOM clobbering has no bounded tool in Boundhound today -- there is no nuclei template or scanner wired in through `bh-exec` that detects this class of issue, and this is stated plainly rather than implying automated coverage. Identifying a candidate requires manual review of a target's client-side script for unguarded global reads, paired with review of what HTML an injection point actually allows through its sanitizer. Confirming exploitability is done through `/burp` within scope: submit a crafted element with a colliding `id`/`name` to the injection point and use the browser console to verify the targeted global now resolves to the injected element instead of its intended value.

## Scope & safety
Testing stays within targets already listed in `scope.yaml`, with every request passing through the Burp MCP guard's deny-by-default scope check. Verification payloads use a harmless, clearly marked element -- never one crafted to trigger a destructive state change or persist beyond what is needed to confirm the collision.

## Remediation
Never read configuration or security-relevant values from an unguarded global lookup; validate the type and origin of any value read from a global before trusting it. Prefer namespaced, non-global state (a module-scoped object or a signed inline script) over relying on implicit global-scope assignment from named DOM elements.
