---
description: Run the Phase 4 verify pass (bh-findings, targeted re-checks via bh-exec, bh-findings) against the active engagement
---

<command-instruction>
Load and follow the `pentest-verify` skill against the active engagement.

1. Confirm an active engagement exists and that at least one of
   `output/recon/recon-map.json`, `output/enum/enum-map.json`, or
   `output/exploit/exploit-map.json` already exists — stop and tell the
   user what's missing (run `/engagement`, `/recon`, `/enum`, and/or
   `/exploit` first) if not.
2. Run `bh-findings` to build the candidate `findings.json`, then for every
   unverified candidate re-screen its target against the engagement's
   current in-scope/out-of-scope lists and re-run its SAME bounded
   confirming check via `bh-exec` — never a heavier scan, and never sqlmap
   (sqli findings are already confirmed) — into
   `output/verify/recheck/`.
3. Run `bh-findings` again to fold the re-check results back in and
   summarize the final `findings.json` for the user: total findings, which
   are `verified:true` vs `verified:false`, and by severity. A finding that
   did not reproduce stays in the report, flagged `verified:false` — it is
   never dropped.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
