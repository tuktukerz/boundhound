---
description: Set engagement mode + scope_enforcement on the active engagement
---

<command-instruction>
Load and follow the `pentest-mode` skill. Update `mode` and `scope_enforcement`
on `engagements/<active>/scope.yaml` per the argument (auto|ctf|bug-bounty|red-team|blue-team|offensive|grey-hat).
Never set `scope_enforcement: none` for any target other than a lab/CTF target you own.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
