---
description: Set engagement mode + scope_enforcement pada engagement aktif
---

<command-instruction>
Load and follow the `pentest-mode` skill. Update `mode` dan `scope_enforcement`
pada `engagements/<aktif>/scope.yaml` sesuai argumen (auto|ctf|bug-bounty|red-team|blue-team|offensive|grey-hat).
Jangan pernah set `scope_enforcement: none` untuk target selain lab/CTF milik sendiri.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
