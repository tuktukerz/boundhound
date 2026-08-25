---
name: saml-attacks
description: "SAML attacks target the XML-based single-sign-on assertion exchange between an identity provider and a service provider -- XML signature wrapping that lets an attacker inject a forged assertion alongside a validly signed one, missing or improperly verified signatures, assertion replay due to weak or absent audience/recipient/expiry checks, and parser issues in how the assertion's XML is processed. Use this skill when a target's single-sign-on login uses SAML (a base64-encoded XML assertion is visible in the login POST or redirect). Triggers: 'saml', 'saml attack', 'xml signature wrapping', 'saml assertion replay', 'saml sso', 'samlresponse'."
version: 1.0.0
phase: ["enum", "verify"]
category: ["web-auth-session"]
tags: ["saml", "sso", "xml", "authentication", "web"]
---

# SAML Attacks

## What it is
SAML authenticates a user by having an identity provider issue a signed XML assertion that a service provider then trusts. Attacks concentrate on the trust boundary between the assertion's structure and its signature: XML signature wrapping moves or duplicates the signed content so the parser reads a different, attacker-modified element than the one the signature actually covers; a service provider that fails to verify the signature at all, or verifies it against the wrong certificate, accepts an assertion the attacker forged outright; and an assertion missing (or with an unchecked) audience, recipient, or expiry condition can be replayed against a different service provider or reused after it should have expired.

## Where it shows up
Any enterprise or business-to-business single-sign-on login that produces a base64-encoded XML assertion in a POST body or URL parameter is the entry point. Multi-tenant products that accept SAML from many different customer identity providers are a particularly common place to find weak signature or audience validation, since the service provider has to trust many different signing certificates.

## How Boundhound approaches it
SAML's signature-wrapping and replay flaws are structural XML attacks with no single bounded tool that detects or exploits them end to end in this system. `/enum` and nuclei (through `bh-exec`) can flag a subset of known SAML/SSO misconfigurations where a matching detection template exists, and general recon establishes which login flow uses SAML in the first place. Actually crafting a signature-wrapping payload, stripping or relocating a signature, or replaying a captured assertion is manual work through `/burp` -- intercepting the assertion, decoding and modifying the XML, and resubmitting it within the scope the Burp MCP guard enforces on every request.

## Scope & safety
The service provider endpoint receiving the crafted or replayed assertion must already be in `scope.yaml`; the Burp MCP guard denies by default and blocks submission to anything outside scope. Testing uses the engagement's own identity-provider test accounts, and a crafted assertion is submitted only enough times to prove acceptance or rejection -- Boundhound does not use a forged assertion to establish or maintain a persistent session beyond that proof.

## Remediation
Verify the XML signature over the exact assertion element that will be trusted, using a canonicalization and reference-checking library that resists signature wrapping, not a naive text match. Enforce audience, recipient, and expiry conditions on every assertion, and pin the expected signing certificate per identity provider rather than accepting any certificate the assertion happens to carry.
