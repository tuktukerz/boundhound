---
name: postmessage-abuse
description: "postMessage abuse covers flaws in a page's use of the window.postMessage cross-origin messaging API -- sending a message to a wildcard target origin, or receiving one without validating the sender's origin and data shape before acting on it. Use this skill when an embedded widget, OAuth popup, or cross-frame integration sends or receives postMessage traffic without strict origin checks. Triggers: 'postmessage abuse', 'window.postmessage vulnerability', 'missing origin check postmessage', 'cross-frame messaging flaw'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-client"]
tags: ["postmessage", "javascript", "client-side", "web"]
---

# postMessage Abuse

## What it is
postMessage abuse covers flaws in how a page implements the `window.postMessage` cross-origin messaging API: sending a message without specifying a precise target origin (using `*` instead of the intended recipient's origin), or receiving a message without validating the event's origin and data shape before acting on it. Either mistake lets an untrusted page send or intercept messages that the vulnerable page then treats as trusted, which can lead to data leakage, DOM-based cross-site scripting, or a state change triggered from an attacker-controlled origin.

## Where it shows up
Embedded widgets, OAuth/SSO popup flows, cross-frame communication between a main application and an iframe (payment widgets, chat overlays, third-party integrations), and any page whose `message` event listener checks `event.origin` loosely or not at all. A listener that calls `eval`, sets `innerHTML`, or triggers navigation or a state change directly from `event.data` without an origin check is a high-severity instance of this pattern.

## How Boundhound approaches it
postMessage abuse has no bounded tool in Boundhound today -- there is no nuclei template or scanner wired in through `bh-exec` that inspects client-side message-handling logic, and this is stated plainly instead of implying coverage that does not exist. Finding and confirming this class of issue is manual work: reviewing a target's client-side script, retrieved within scope, for `postMessage` senders using a wildcard target origin and listeners missing an origin check, then verifying exploitability through `/burp` -- intercepting and replaying page traffic, or using the browser console to send a crafted message from a test page and observing whether the listener acts on it.

## Scope & safety
Any page or script reviewed, and any crafted test message sent, is limited to targets already listed in `scope.yaml`, with all traffic passing through the Burp MCP guard's deny-by-default scope check. Test messages carry a harmless marker payload only -- never one designed to trigger a real state change on a live account outside the authorized test account.

## Remediation
Always specify an exact target origin (never `*`) when sending a message, and always validate `event.origin` against an explicit allow-list before trusting `event.data` on receipt. Treat message content as untrusted input requiring the same validation as any other external input.
