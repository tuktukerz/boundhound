---
description: Mulai engagement pentest baru — isi scope, set aktif, nyalakan container
---

<command-instruction>
Load and follow the `pentest-mode` skill.

1. Tanyakan ke user: nama engagement, authorization (bukti izin), mode, dan daftar in_scope/out_of_scope.
2. Run (plugin mode vs dev mode: see the `pentest-mode` skill's "Invoking the
   scripts" section): `node "${CLAUDE_PLUGIN_ROOT}/bin/omop-engagement.mjs" <nama>`
   — dev mode fallback (repo checkout, not installed as a plugin): `node
   bin/omop-engagement.mjs <nama>`
3. Tulis jawaban user ke `engagements/<nama>/scope.yaml` (ikuti template).
4. Ingatkan: semua tool HANYA boleh dijalankan lewat `omop-exec`.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
