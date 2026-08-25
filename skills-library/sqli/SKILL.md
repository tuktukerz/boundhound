---
name: sqli
description: "SQL injection happens when untrusted input reaches a SQL query without proper parameterization, letting an attacker change the query's logic to read data outside its intended scope, bypass authentication, or infer database structure through error messages, UNION results, or altered application behavior. Use this skill when a web endpoint's input (form field, query-string parameter, header, or JSON body) appears to be concatenated into a database query -- login forms, search boxes, ID/filter parameters, and reporting endpoints are common candidates. Triggers: 'sql injection', 'sqli', 'union select', 'error-based sql', 'sqlmap', 'database injection'."
version: 1.0.0
phase: ["enum", "exploit"]
category: ["web-injection"]
tags: ["sqli", "database", "injection", "sqlmap", "web"]
---

# SQL Injection

## What it is
SQL injection is an injection flaw where user-controlled input is interpreted as part of a SQL statement instead of as pure data. Depending on how the application surfaces query results, an attacker can pull back extra rows (UNION-based), trigger distinguishable database errors (error-based), or infer information indirectly through timing or boolean differences (covered separately under blind-sqli). The root cause is always the same: the query string and the untrusted input were never properly separated.

## Where it shows up
Parameters that look like they feed a `WHERE`, `ORDER BY`, or `LIKE` clause -- numeric IDs, search terms, sort keys, filter values -- are the first places to check. Login forms, "forgot password" flows, reporting/export endpoints, and any API parameter that maps closely to a database column name are all common entry points. A single quote, backslash, or SQL comment sequence causing a changed response, a database error page, or a different result count is the classic signal.

## How Boundhound approaches it
During `/enum`, Boundhound runs nuclei's SQL-injection detection templates (through `bh-exec`) against discovered endpoints to flag likely injection points cheaply and safely. Once a candidate parameter is identified, `/exploit` hands it to sqlmap (also through `bh-exec`) to produce a bounded, non-destructive proof of vulnerability -- confirming the injection and showing what an attacker could reach. sqlmap runs in Boundhound's strictly bounded mode: it is used to prove the vulnerability exists, not to weaponize it. Flags for dumping data, spawning an OS shell, or reading/writing files (`--dump`, `--os-shell`, `--file-read`, `--file-write`, and equivalents) are denied by the safety layer regardless of what is requested.

## Scope & safety
Every target and parameter tested must already be inside `scope.yaml`; anything outside scope is refused before a single request goes out (deny-by-default). All tool invocations run through `bh-exec`, which enforces the bounded sqlmap flag set described above -- proof-of-vulnerability only, never data exfiltration or code execution.

## Remediation
Use parameterized queries or prepared statements everywhere user input reaches SQL; never build queries by string concatenation. Apply least-privilege database accounts and input validation as defense in depth, not as the primary control.
