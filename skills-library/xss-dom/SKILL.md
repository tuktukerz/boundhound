---
name: xss-dom
description: "DOM-based cross-site scripting occurs entirely on the client: untrusted data (from the URL fragment, document.referrer, postMessage, or similar) flows into a dangerous JavaScript sink -- innerHTML, document.write, eval, or a framework's unsafe-render path -- without ever being processed by the server, so a normal server-side scan can miss it. Use this skill when a page's client-side JavaScript reads a source like location.hash or location.search and writes it into the DOM without sanitization. Triggers: 'dom xss', 'dom-based xss', 'client-side xss', 'javascript sink injection', 'innerHTML injection'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["xss", "dom", "client-side", "javascript", "web"]
---

# DOM-Based Cross-Site Scripting

## What it is
DOM XSS is a client-side-only variant of cross-site scripting: the vulnerable data flow never touches the server. JavaScript already running in the page reads an untrusted source (URL fragment, document.referrer, window name, a postMessage payload) and passes it into a sink that renders raw HTML or executes code (innerHTML, outerHTML, document.write, eval, setTimeout with a string argument, or a templating helper misused with an unsafe binding). Because the server never sees the malicious value in this pattern, purely server-side scanning under-detects it.

## Where it shows up
Single-page applications and any page with hash-routing, client-side search/filter widgets that read location.search, and pages that consume postMessage data from another window or iframe are the common places to look. Reviewing bundled/minified JavaScript for the source-to-sink pattern above is often necessary alongside black-box testing, since the vulnerable code may never make a distinguishing server request.

## How Boundhound approaches it
`/enum` runs nuclei's XSS detection templates (through `bh-exec`), including checks tagged for DOM-based patterns where matching signatures exist, and ffuf (through `bh-exec`, also `/enum`) helps enumerate client-side routes and parameters worth exercising. Because the vulnerable logic lives in client-side JavaScript, confirming it is primarily manual: `/burp` is used to intercept and replay requests that carry a candidate payload in the URL fragment or query string, and observed browser execution confirms whether the sink actually fires. Every `/burp` call goes through the Burp MCP scope guard, deny-by-default the same as `bh-exec`.

## Scope & safety
Only in-scope hosts from `scope.yaml` are exercised. Verification uses inert markers (a harmless console-log or alert call) purely to confirm the sink executes -- no payload is used to read cookies, tokens, or other page data beyond what is needed to prove the sink fires.

## Remediation
Avoid unsafe sinks entirely where possible (prefer textContent over innerHTML); where HTML must be set dynamically, sanitize with a well-maintained sanitization library first. Validate and encode any data taken from the URL, postMessage, or document.referrer before it reaches a rendering or execution sink.
