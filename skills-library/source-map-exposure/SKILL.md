---
name: source-map-exposure
description: "Source map exposure is a `.map` file left reachable alongside a minified JavaScript bundle, letting anyone fetch it and reconstruct the original, unminified source -- original variable and function names, inline comments, and sometimes internal API paths or endpoint logic that the minified bundle itself never reveals. Use this skill against any target serving built front-end JavaScript, since a build pipeline can generate and deploy source maps without anyone deciding they should be public. Triggers: 'source map exposure', 'exposed .map file', 'javascript source map leak', 'minified bundle deobfuscation', 'sourcemappingurl disclosure'."
version: 1.0.0
phase: ["enum"]
category: ["info-disclosure"]
tags: ["source-maps", "javascript", "ffuf", "web"]
---

# Source Map Exposure

## What it is
A source map is a build artifact that maps a minified JavaScript file back to its original, readable source -- it exists so a developer's browser can show real file names and line numbers while debugging production code. When that same `.map` file is deployed to a public web root alongside the bundle it describes, anyone can fetch it and get the same readable source back: original variable and function names, inline comments, and code structure that the minified bundle was specifically built to obscure. The minification an application relies on for a smaller, less-readable bundle is undone entirely if its source map ships alongside it.

## Where it shows up
A `//# sourceMappingURL=` comment at the end of a minified JavaScript file naming a `.map` file that resolves when requested directly. It is most likely on targets whose build process wasn't explicitly configured to exclude source maps from a production deployment, which is a common default rather than a deliberate choice either way. Source maps sometimes reveal more than just readable code -- comments describing internal logic, or hardcoded values -- that were never meant for anyone outside the development team.

## How Boundhound approaches it
During `/enum`, ffuf (through `bh-exec`) requests the `.map` path named in each discovered JavaScript file's `sourceMappingURL` comment, as well as the conventional `<bundle>.js.map` naming pattern, to check whether the map resolves. Where one does, Boundhound reads enough of the mapped source to confirm what it reveals -- comments, internal paths, or embedded values worth flagging -- without fully reconstructing and archiving the application's entire original source tree from the map.

## Scope & safety
Only hosts and bundles already in scope under `scope.yaml` are checked, with `bh-exec` refusing anything outside that boundary before a request is sent. Fetching a source map is a normal, read-only request identical to what any browser's developer tools would trigger; confirming exposure and noting what it reveals is the goal, not exporting a full deobfuscated copy of the application.

## Remediation
Exclude source maps from production builds, or restrict them to an internal-only host that isn't reachable from the public internet, so debugging capability doesn't ship as a side effect of an otherwise sensible build step. Where source maps are genuinely needed in production for error-tracking tooling, gate access to them behind authentication rather than leaving them world-readable next to the bundle.
