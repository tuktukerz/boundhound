---
name: http-request-smuggling
description: "HTTP request smuggling exploits disagreement between a front-end proxy/load balancer and a back-end server over where one HTTP request ends and the next begins -- typically caused by conflicting or ambiguous Content-Length and Transfer-Encoding headers -- letting an attacker smuggle a second, hidden request that the back-end processes as if it came from the next legitimate client. Use this skill when a target sits behind a reverse proxy, load balancer, or CDN and multiple systems in the chain parse HTTP framing independently. Triggers: 'http request smuggling', 'request smuggling', 'desync attack', 'content-length transfer-encoding conflict', 'http desync'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-injection"]
tags: ["request-smuggling", "desync", "web", "injection"]
---

# HTTP Request Smuggling

## What it is
Request smuggling arises when two systems in a request's path (a front-end proxy and a back-end application server, most commonly) disagree about a request's length -- one trusting the declared content length, the other trusting chunked transfer encoding, or both headers being present with conflicting values. That disagreement lets an attacker craft a request whose "extra" bytes are interpreted by the back-end as the start of a second, attacker-controlled request, which can then be prepended to -- and processed as part of -- whatever the next real client sends.

## Where it shows up
Any target behind a reverse proxy, CDN, or load balancer where the front end and back end might parse HTTP framing differently is a candidate -- this is a chain-topology issue more than a single-endpoint one, so it's worth checking whenever infrastructure recon shows a proxy/CDN in front of the origin. Confirmation requires careful differential timing or response-queue analysis (does a crafted ambiguous request cause the next response on the same connection to come back wrong or delayed) rather than a single request/response pair.

## How Boundhound approaches it
`/enum` runs nuclei (through `bh-exec`) against discovered endpoints, and its template set includes a small number of checks for known, CVE-specific smuggling conditions, but general desync detection isn't something a signature-based scan reliably catches -- it depends on live, connection-level timing behavior between front end and back end. Boundhound does not currently have a bounded tool that performs desync/timing-based smuggling detection or exploitation, and this skill says so plainly rather than implying otherwise. The safe path is manual verification through `/burp`: within scope, send carefully-crafted ambiguous-framing requests via Repeater and observe the response queue for smuggling behavior. A dedicated bounded request-smuggling tool can be brought in through `bh-exec` in a future phase.

## Scope & safety
Testing is limited to in-scope hosts from `scope.yaml`. Because smuggling probes can affect other requests sharing the same back-end connection, verification is done carefully and minimally -- proving the framing disagreement exists, not attempting to hijack or read another user's live request/response as part of this proof step.

## Remediation
Prefer HTTP/2 end-to-end between proxy and back end where possible, since chunked/content-length ambiguity is a HTTP/1.1 framing problem. Where HTTP/1.1 must be used, ensure front end and back end agree strictly on framing (reject requests carrying both a content-length and a transfer-encoding header, and normalize/reject ambiguous framing at the front end) rather than passing ambiguous requests through.
