---
description: Start a new pentest engagement — fill in scope, mark it active, bring up the container
---

<command-instruction>
Load and follow the `pentest-mode` skill.

1. Ask the user: engagement name, authorization (proof of authorization), mode, and the in_scope/out_of_scope lists.
2. Run (plugin mode vs dev mode: see the `pentest-mode` skill's "Invoking the
   scripts" section): `node "${CLAUDE_PLUGIN_ROOT}/bin/bh-engagement.mjs" <name>
   --data-dir "${CLAUDE_PLUGIN_DATA}"` — dev mode fallback (repo checkout, not
   installed as a plugin): omit `--data-dir` and run `node
   bin/bh-engagement.mjs <name>`
3. Write the user's answers into `engagements/<name>/scope.yaml` (follow the template).
4. Remind them: every tool may ONLY be run through `bh-exec`.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
