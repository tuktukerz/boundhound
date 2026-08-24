# OmOP-CC

**Autonomous pentest agent, built natively on Claude Code.**

> Bukan fork. OmOP ([`zakirkun/oh-my-open-pentest`](https://github.com/zakirkun/oh-my-open-pentest)) dipakai sebagai tambang skill & acuan pola — orchestrator, safety layer, dan integrasinya dibangun dari nol di atas primitives Claude Code (skills, subagents, hooks).

---

## 🚧 Status: Fase 0 — Fondasi & Safety

```
[0] Fondasi & Safety   ██████████ selesai   <- kamu di sini
[1] Recon              ░░░░░░░░░░ belum
[2] Enumeration        ░░░░░░░░░░ belum
[3] Exploitation       ░░░░░░░░░░ belum
[4] Verification       ░░░░░░░░░░ belum
[5] Reporting          ░░░░░░░░░░ belum
[6] Orchestrator       ░░░░░░░░░░ belum
[7] Ekspansi           ░░░░░░░░░░ belum
```

**Fase 0 sengaja nol kemampuan serang.** Belum ada nmap, nuclei, sqlmap — cuma `curl` sebagai tool uji jembatan. Prinsipnya: **pagar duluan, senjata belakangan.** Tidak ada tool serang yang boleh terpasang sebelum lapisan keamanan ini terbukti lewat test otomatis.

## Kenapa ini dibikin

Pentest agent otonom itu berbahaya kalau nggak ada batas keras. Kebanyakan tool "AI pentest" mengandalkan agent untuk *patuh* pada scope — itu imbauan, bukan penegakan. OmOP-CC membalik itu: **agent secara teknis tidak bisa** menyentuh target di luar scope, karena penegakannya ada di lapisan yang agent tidak kontrol (git-tracked hook + choke-point CLI), bukan di prompt.

## Cara kerja keamanannya

```
User / Agent
    │
    ▼
┌─────────────────────────┐   perintah langsung ke curl/nmap/dst?
│  PreToolUse hook         │──────────────► DENY (bypass diblokir)
│  (scope-guard.mjs)       │
└─────────────────────────┘
    │ lolos via omop-exec
    ▼
┌─────────────────────────┐   target di luar scope.yaml?
│  omop-exec               │──────────────► DENY + audit log
│  (choke point)           │
│  scope → safety → audit │
└─────────────────────────┘
    │ ALLOW
    ▼
┌─────────────────────────┐
│  docker exec             │  tool jalan di container terisolasi
│  (omop-<engagement>)     │
└─────────────────────────┘
```

- **Deny-by-default** — target tidak eksplisit di `in_scope` → ditolak. Ragu → ditolak.
- **Fail-closed** — `scope.yaml` rusak atau tidak ada engagement aktif → semua ditolak.
- **`out_of_scope` menang** atas `in_scope` — pengecualian eksplisit selalu diprioritaskan.
- **Dua lapis independen** — hook mencegah agent *menghindari* `omop-exec`; `omop-exec` sendiri yang melakukan pengecekan sebenarnya.
- **Audit penuh** — setiap keputusan (ALLOW/DENY) tercatat: timestamp, target, tool, alasan, otorisasi.

Semua diverifikasi lewat [`test/acceptance.test.mjs`](test/acceptance.test.mjs) — bukan klaim, ada buktinya:

```
75 pass · 1 skip (Docker smoke, butuh container hidup) · 0 fail
```

## Quickstart

```bash
bun install
bun test                        # 75 pass / 1 skip

bin/omop-container up smoke     # nyalain container tool
node bin/omop-engagement.mjs acme   # scaffold engagement baru -> isi scope.yaml
node bin/omop-exec.mjs curl --target api.acme.io -- -I   # jalanin tool via choke point
```

## Struktur

```
.claude/
  skills/pentest-mode/     skill aktif (dipanen dari OmOP, di-tuning ke sistem kita)
  commands/                /engagement, /mode
  settings.json            registrasi PreToolUse hook
bin/
  omop-exec.mjs            choke point: scope + safety + audit -> docker exec
  omop-engagement.mjs      scaffold engagement baru
  omop-container           lifecycle container Docker
hooks/scope-guard.mjs      cegah bypass omop-exec
src/
  scope/                   parser + matcher (deny-by-default) + fail-closed resolver
  safety/                  blok aksi destruktif/DoS
  catalog/                 tools-catalog.json loader (schema ToolEntry ala OmOP)
  guard/                   klasifikasi command, anti-bypass
  audit/                   audit log JSONL
docker/Dockerfile          image ramping — cuma tool uji jembatan
skills-library/            arsip skill OmOP (referensi, belum aktif)
docs/
  ARCHITECTURE.md          peta besar & 8 fase
  specs/, plans/           spec & implementation plan per fase
```

## Prinsip desain

1. **Safety sebelum kemampuan.** Setiap fase kemampuan baru (recon, exploit, dst) dibangun di atas fondasi yang sudah lolos test — bukan sebaliknya.
2. **Panen, jangan fork.** Skill OmOP (250 `SKILL.md`) diambil sebagai bahan baku, ditaruh di `skills-library/`, dipromosikan ke skill aktif satu-satu sambil di-tuning — bukan diimpor mentah-mentah.
3. **Enforcement, bukan imbauan.** Kalau sesuatu harus benar, itu dipaksa oleh kode/hook — bukan cuma ditulis di instruksi agent.
4. **Setiap task = TDD + review adversarial.** Dibangun lewat subagent-driven development: setiap modul ditulis test-first, di-review subagent independen, dan setiap temuan (termasuk beberapa bug nyata — bypass guard, hook fail-open, `import.meta.main` yang mati di Node) ditutup dengan regression test sebelum lanjut.

## Roadmap

Lihat [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) untuk peta lengkap 8 fase, keputusan desain, dan alasan di balik setiap pilihan arsitektur.

---

*Dibangun secara iteratif: brainstorming → grilling → spec → plan → subagent-driven implementation, tiap langkah direview sebelum lanjut.*
