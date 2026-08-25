---
name: oauth-misconfig
description: "OAuth misconfiguration covers implementation flaws in an OAuth 2.0 / OpenID Connect authorization flow -- a redirect_uri validated only by prefix or substring match, letting an attacker steal an authorization code or token; a missing or predictable state parameter enabling login CSRF into the flow; implicit-flow tokens leaking via the URL fragment or referrer; or a client that skips validating a token's audience/issuer. Use this skill when a target integrates a third-party sign-in flow (OAuth or OIDC) and the authorization request or callback can be observed or manipulated. Triggers: 'oauth misconfig', 'oauth redirect_uri', 'oauth state parameter', 'oidc misconfiguration', 'authorization code leak', 'oauth sign in flow'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["oauth", "oidc", "sso", "authentication", "web"]
---

# OAuth Misconfiguration

## What it is
OAuth 2.0 and OpenID Connect delegate authentication to a third-party provider through a redirect-based handshake, and most real-world flaws live in how the relying application implements that handshake rather than in the protocol itself. Common failure modes: a `redirect_uri` validated only by prefix or substring match, so an attacker-controlled URL that merely starts with or contains the expected value is accepted; a missing or reused `state` parameter that lets an attacker link their own OAuth flow to a victim's browser (login CSRF); and implicit-flow access tokens returned in a URL fragment, where they can leak via referrer headers or browser history.

## Where it shows up
Any third-party sign-in button, SSO integration, or OIDC-based login is a candidate. The redirect handshake itself -- the authorization request's `redirect_uri` and `state` parameters, and the callback endpoint that receives the code or token -- is where these flaws concentrate, along with the token-exchange step that should validate `aud` and `iss` claims before trusting a token.

## How Boundhound approaches it
OAuth/OIDC flaws are configuration and logic issues with no single bounded tool that exploits them end to end. `/enum` uses ffuf and nuclei (through `bh-exec`) to enumerate the authorization, callback, and token endpoints a target exposes, and to flag a subset of known OAuth/OIDC misconfiguration patterns where a matching nuclei template exists. Actually testing `redirect_uri` validation strength, `state` handling, and token-audience checks is manual, operator-directed work through `/burp` -- intercepting and modifying the authorization request and callback within the scope the Burp MCP guard enforces on every request.

## Scope & safety
The relying application and the identity provider endpoints being tested must both already be in `scope.yaml`; requests to anything outside scope are refused before they are sent. Testing uses the engagement's own test accounts on the provider side wherever possible, and stops at proving a redirect or state weakness exists -- Boundhound does not use a captured code or token to pivot into a real user's account beyond what demonstrates the flaw.

## Remediation
Validate `redirect_uri` against an exact allowlist, not a prefix or substring match. Always generate a unique, unpredictable `state` (and, for OIDC, `nonce`) value per authorization request and verify it on the callback. Prefer the authorization-code flow with PKCE over the implicit flow, and always validate a received token's `aud` and `iss` before trusting its claims.
