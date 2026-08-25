---
description: Run the Phase 5 report pass (bh-report) against the active engagement and summarize the result
---

<command-instruction>
Load and follow the `pentest-report` skill against the active engagement.

1. Confirm an active engagement exists and
   `output/verify/findings.json` is present — stop and tell the user what's
   missing (run `/engagement` and/or `/verify` first) if not.
2. Run `bh-report` (plugin mode vs dev mode: see the `pentest-report`
   skill's "Invoking the script" section) to render
   `output/report/report.md`. A broken scope makes `bh-report` fail-closed
   (exit code 3) — if that happens, tell the operator the scope needs to be
   fixed before a report can be generated, rather than producing one by
   hand.
3. Read the generated `report.md` and summarize it for the operator:
   engagement metadata, the severity-count table, how many findings are
   verified, and the top findings by severity. Never alter `report.md` and
   never add anything to the summary beyond what the file already states —
   the report renders only verified engagement data and never invents
   findings, severities, or evidence.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
