---
description: List, activate, or deactivate a skills-library technique playbook
---

<command-instruction>
Run `bh-skill` to list, promote, or demote a skills-library technique
playbook for the operator.

**What this does.** `skills-library/` holds 81 self-authored technique
playbooks (source, not loaded by the plugin). `.claude/skills/` holds the
active skill set the plugin actually loads. `promote <slug>` copies
`skills-library/<slug>/` into `.claude/skills/<slug>/`, turning that
playbook on; `demote <slug>` removes it again. This never invents a new
capability — a promoted skill only reasons about tools already reachable
through `bh-exec`.

**The 8 core pipeline skills cannot be demoted**: `pentest-recon`,
`pentest-enum`, `pentest-exploit`, `pentest-verify`, `pentest-report`,
`pentest-workflow`, `pentest-burp`, `pentest-mode`. These must always stay
active for the phase pipeline (`/recon` `/enum` `/exploit` `/verify`
`/report` `/fullscan` `/burp` `/mode`) to keep working. `bh-skill` refuses to
remove any of them, and also refuses to remove any other active skill that
has no matching entry left in `skills-library/` (nothing to restore it
from).

**Invoking the script: plugin mode vs dev mode.** Same convention as every
other command in this plugin:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/bh-skill.mjs" <list|promote|demote> [slug] [--force]
```

Run it exactly as written — Claude Code resolves `${CLAUDE_PLUGIN_ROOT}` to
an absolute path inline before this text reaches you. If it still reads as
literal placeholder text, this loaded as a plain project skill/command, not
an installed plugin (dev mode, working inside a clone of the boundhound
repo) — in that case run the repo-relative form from the repo root instead:
`node bin/bh-skill.mjs <list|promote|demote> [slug] [--force]`.

**Subcommands:**

1. `list` (also the default with no subcommand) — list every skill in
   `skills-library/` with its category, marking which ones are already
   active. Use this first when the operator isn't sure of a slug.
2. `promote <slug>` — activate a library skill. Report the confirmation
   back to the operator, including the skill's Triggers phrases, so they
   know what request wording will now engage it. If the slug is already
   active, say so — this is idempotent, not an error. Pass `--force` only
   if the operator explicitly wants to overwrite an active copy that may
   have drifted from the library source.
3. `demote <slug>` — deactivate a promoted library skill. If `bh-skill`
   refuses (a core skill, or an active skill with no library match), relay
   the refusal reason to the operator rather than trying to remove the
   folder by hand.

Never edit files under `.claude/skills/` or `skills-library/` directly to
work around `bh-skill` — always go through the script so behavior stays
consistent with what `bin/bh-skill.test.mjs` verifies.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
