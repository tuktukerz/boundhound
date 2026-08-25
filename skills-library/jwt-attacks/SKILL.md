---
name: jwt-attacks
description: "JWT attacks target flaws in how a JSON Web Token's signature is verified or how its claims are trusted -- algorithm confusion (accepting 'none' or forcing RS256 down to HS256), a weak or leaked signing secret, missing signature verification, key-lookup (kid/JWKS) confusion, and trusting unverified claims such as role or user_id without checking the signature at all. Use this skill when a session or API auth token looks like a JWT (three base64url segments separated by dots) and its signature or claims might not be properly enforced. Triggers: 'jwt', 'json web token', 'jwt attack', 'jwt none algorithm', 'jwt confusion', 'weak jwt secret'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["jwt", "token", "authentication", "session", "web"]
---

# JWT Attacks

## What it is
JSON Web Tokens carry a header, a claims payload, and a signature, and the receiving application is supposed to trust the claims only after verifying that signature. JWT attacks target the verification step itself: switching the header's `alg` to `none` and stripping the signature, forcing an asymmetric-key check (RS256) down to a symmetric one (HS256) so the public key can be reused as the HMAC secret, brute-forcing a weak signing secret, or exploiting a `kid`/JWKS lookup that lets an attacker point verification at a key they control.

## Where it shows up
Any endpoint that accepts a JWT as a bearer token, cookie, or custom header is a candidate -- API authentication, single sign-on handoffs, and stateless session tokens are the most common carriers. The signal worth chasing is a token that decodes cleanly into three base64url segments, where the application's behavior changes based on claims like `role`, `user_id`, or `is_admin` inside that payload.

## How Boundhound approaches it
Token analysis and signature/claim tampering are verified manually through `/burp`, within the scope the Burp MCP guard enforces on every request -- decoding a captured token, testing whether the server accepts a re-signed or unsigned variant, and confirming which claims actually change server-side behavior. `/enum`'s nuclei templates (through `bh-exec`) can flag a subset of known JWT misconfigurations where a matching detection template exists, giving a starting signal before the manual work in `/burp`. Boundhound does not run an automated JWT-cracking or signature-forging tool on its own; there is no bounded tool in this system that does that end to end.

## Scope & safety
Every host a captured or forged token is replayed against must already be in `scope.yaml`; the Burp MCP guard denies by default and blocks a request to any target outside scope before it is sent. Verification uses test accounts provisioned for the engagement and stops at proving the signature or claim check can be bypassed -- Boundhound does not use a forged token to pivot into further access beyond what is needed to demonstrate the flaw.

## Remediation
Always verify the JWT signature using a fixed, expected algorithm and key -- never derive the algorithm from the token's own header, and never allow `none`. Keep signing secrets long, random, and rotated; for asymmetric schemes, keep the public key out of any code path that could be reused as an HMAC secret. Validate `kid` values against a known key set rather than trusting an attacker-supplied key location.
