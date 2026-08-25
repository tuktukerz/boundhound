---
name: blind-sqli
description: "Blind SQL injection is a variant of SQL injection where the application never reflects query results, errors, or database output directly in the response -- so the attacker has to infer true/false conditions from boolean differences (does the page change?) or from time delays (does the response take longer?) instead of reading data straight off the page. Use this skill when a parameter looks injectable but standard error-based or UNION-based probes produce no visible difference, and the only feedback available is a subtly different response body, status code, or response time. Triggers: 'blind sql injection', 'blind sqli', 'time-based sqli', 'boolean-based sqli', 'time delay injection'."
version: 1.0.0
phase: ["enum", "exploit"]
category: ["web-injection"]
tags: ["sqli", "blind", "database", "injection", "sqlmap"]
---

# Blind SQL Injection

## What it is
Blind SQL injection exploits the same underlying flaw as regular SQL injection -- unsanitized input reaching a database query -- but the application gives no direct visual or error-based feedback. Confirmation instead relies on boolean-based probes (a condition that is true renders differently than one that is false) or time-based probes (an injected delay-style function that shows up in response timing). Because each bit of information takes many requests to extract, blind SQL injection is slower to confirm and far slower to exploit than its visible counterpart.

## Where it shows up
Any parameter that looks database-backed but shows identical output regardless of injected quotes or comments is a blind-sqli candidate: search filters, filtering/sorting parameters, and API fields that return a fixed-shape response (e.g., a boolean "found"/"not found", or an unconditional 200 with no query results embedded) are typical. A consistent, reproducible delay when a time-delay-style payload is appended to a parameter is the strongest signal.

## How Boundhound approaches it
`/enum` runs nuclei's blind/time-based SQL-injection detection templates (through `bh-exec`) to flag candidates using safe, bounded delay probes. Confirmed candidates move to `/exploit`, where sqlmap (through `bh-exec`) runs its boolean-based-blind and time-based-blind techniques to produce a bounded proof of vulnerability -- for example, confirming that an injected condition measurably changes response timing or content. As with regular sqli, sqlmap runs in Boundhound's strictly bounded mode: data-dumping, OS-shell, and file-read/write flags are denied by the safety layer, so this stays a proof step, never extraction or code execution.

## Scope & safety
Targets and parameters must be within `scope.yaml` before any probe runs; out-of-scope hosts are refused deny-by-default. Time-based probes are inherently noisier on a live target, so Boundhound keeps delay values small and request counts bounded -- every request still goes through `bh-exec`'s enforcement of the non-destructive, bounded sqlmap flag set.

## Remediation
The fix is identical to standard SQL injection: parameterized queries/prepared statements, never string-concatenated SQL. Additionally, avoid designing endpoints whose timing or response shape leaks conditional information, and apply rate limiting to slow down blind extraction attempts.
