---
name: pentest-burp
description: "Explain boundhound's Burp Suite safety model, or mirror the active engagement's scope into Burp's own Target Scope. Triggers: 'burp', 'burp suite', 'burp mcp', 'burp scope', 'burp target scope', 'mirror scope into burp', 'bh-burp-scope'."
phase: ["burp"]
tools: ["Burp MCP (host-side — not bh-exec)"]
---

<command-instruction>
Load and follow the `pentest-burp` skill.

1. Confirm an active engagement exists, its `authorization` is on record,
   and `in_scope` is non-empty — stop and tell the operator what's missing
   (run `/engagement` first) if not.
2. Explain the safety model in plain terms when asked: Burp Suite (Burp Pro,
   required for active scan) runs on the operator's host, entirely outside
   boundhound's engagement container, and a Burp MCP tool call sends its own
   HTTP request directly to the target — so, unlike every other tool in this
   system, it never passes through `bh-exec`. Instead, a PreToolUse scope
   guard (`hooks/scope-guard.mjs` + `src/guard/burp-guard.mjs`) intercepts
   every Burp MCP tool call and scope-checks its target deny-by-default: no
   active scope, an unresolved or ambiguous target, a suspicious target, or
   an out-of-scope target are all denied and written to the engagement's
   audit log. A denied call is skipped, not forced — never retried with a
   relaxed target and never bypassed.
3. Run `bh-burp-scope` (plugin mode vs dev mode: see the `pentest-burp`
   skill's "Defense in depth" section) so the operator can load the result
   into Burp itself:
   ```
   node "${CLAUDE_PLUGIN_ROOT}/bin/bh-burp-scope.mjs" --data-dir "${CLAUDE_PLUGIN_DATA}"
   ```
   Dev mode: `node bin/bh-burp-scope.mjs` from the repo root, no
   `--data-dir`. This writes `output/burp/target-scope.json` from the active
   engagement's `scope.yaml` (fail-closed: nothing is written without a
   valid active engagement and scope). Tell the operator to load that file
   into Burp via **Target → Scope** — this mirrors scope into Burp as
   defense in depth, it does not replace the PreToolUse guard, which keeps
   enforcing scope on every Burp MCP call regardless.
4. Be honest about current scope: the guard and its audit trail are live and
   tested today; boundhound does not drive a Burp scan end-to-end on its
   own — that still requires the operator's own Burp Pro installation plus
   a wired Burp MCP server, set up and validated separately.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
