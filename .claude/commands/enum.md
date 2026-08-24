---
description: Run the Phase 2 enum chain (ffuf, nuclei, bh-enum-map) against the active engagement
---

<command-instruction>
Load and follow the `pentest-enum` skill against the active engagement.

1. Confirm an active engagement exists and that
   `output/recon/recon-map.json` already exists — stop and tell the user
   what's missing (run `/engagement` and/or `/recon` first) if not.
2. Read `recon-map.json`'s `http_services` and re-screen each host against
   the engagement's current in-scope/out-of-scope lists, then run `ffuf`
   for content discovery and `nuclei` for vulnerability/misconfiguration
   detection against every screened host — every one of these goes through
   `bh-exec`, never direct.
3. Run `bh-enum-map` to normalize everything into `enum-map.json` and
   summarize the result for the user.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
