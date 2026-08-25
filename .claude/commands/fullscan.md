---
description: "Run the full Phase 6 engagement chain (bh-fullscan: recon -> enum -> exploit -> findings -> report) against the active engagement"
---

<command-instruction>
Load and follow the `pentest-workflow` skill against the active engagement.

1. Confirm an active engagement exists, its `authorization` is on record,
   and `in_scope` is non-empty — stop and tell the user what's missing (run
   `/engagement` first) if not.
2. Run `bh-fullscan` (plugin mode vs dev mode: see the `pentest-workflow`
   skill's "Invoking the script" section). Pass `--no-exploit` when the
   operator asks for a non-intrusive run — this skips the `exploit:sqlmap`
   stage and still produces recon + enum + a report from what those two
   phases found. Every tool step the chain runs — subfinder, httpx, nmap,
   nuclei, ffuf, and (unless `--no-exploit` was passed) sqlmap — still goes
   through `bh-exec` (scope + safety + audit + container), exactly like a
   manual `/recon`/`/enum`/`/exploit` run would; a step `bh-exec` denies is
   skipped, not forced, and never aborts the rest of the run. A broken or
   unauthorized scope makes `bh-fullscan` fail-closed (exit code 3) — if
   that happens, tell the operator the scope needs to be fixed before a
   fullscan can run, rather than running any stage by hand.
3. For a long-running or previously interrupted engagement, see the
   `pentest-workflow` skill's "Resilience" section and pass whichever of
   these the operator wants (all optional, all off by default):
   - `--resume` — continue an interrupted scan instead of starting over,
     skipping steps already completed (tracked in
     `engagements/<active>/output/fullscan-state.json`).
   - `--max-retries N` — retry a transient tool failure (a network blip or
     tool crash) up to `N` times, always re-running the identical bounded
     `bh-exec` command; a DENY is never retried.
   - `--max-steps N` / `--max-steps-per-stage N` — a hard ceiling on how
     many tool steps the run performs; these only ever reduce autonomous
     work, never expand it.
4. Read the generated `report.md` and summarize it for the operator:
   engagement metadata, the severity-count table, how many findings are
   verified, the top findings by severity, and whether the exploit stage
   ran. Never alter `report.md`.
5. Mention `/recon`, `/enum`, `/exploit`, `/verify`, and `/report` as the
   way to inspect, re-run, or fine-tune any single stage instead of running
   the whole chain again.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
