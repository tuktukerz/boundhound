---
description: Run the Phase 1 recon chain (subfinder, httpx, nmap, bh-recon-map) against the active engagement
---

<command-instruction>
Load and follow the `pentest-recon` skill against the active engagement.

1. Confirm an active engagement exists with a non-empty `in_scope.domains` —
   stop and tell the user what's missing (run `/engagement` first) if not.
2. Run `subfinder` for passive subdomain discovery, `httpx` for HTTP probing
   of the root domain plus any discovered subdomain that clears the
   `*.<domain>` in_scope rule, then `nmap` against every live host `httpx`
   found — every one of these goes through `bh-exec`, never direct.
3. Run `bh-recon-map` to normalize everything into `recon-map.json` and
   summarize the result for the user.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
