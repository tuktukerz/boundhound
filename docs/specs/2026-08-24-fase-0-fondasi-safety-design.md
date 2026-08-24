# Spec Desain — Fase 0: Fondasi & Safety

**Tanggal:** 2026-08-24
**Status:** draft, menunggu review
**Prasyarat:** tidak ada (fase pertama)
**Prinsip pemandu:** **ikut pola repo rujukan (OmOP)**, tambahkan "teeth" di titik safety sebagai upgrade.

---

## 1. Tujuan & Non-Tujuan

### Tujuan
Membangun **kerangka repo bergaya OmOP** + **lapisan keamanan yang benar-benar dipaksa**: engagement config (mode + scope), katalog tool deklaratif, jembatan Docker, audit log, dan hook yang memblokir perintah ke luar scope. Semua mengikuti konvensi OmOP; bedanya, `scope_enforcement: strict` di sini **ditegakkan mesin**, bukan sekadar diminta ke agent.

### Non-Tujuan (TEGAS)
- ❌ **Nol kemampuan serang/recon.** Tidak ada tool pentest nyata (nmap/nuclei/dst). Itu Fase 1+.
- ❌ Tidak ada orchestrator/`fullscan`, tidak ada skill fase dipromosikan.
- ❌ Tidak ada report, tidak ada mode-detection cerdas (cukup pemilihan mode manual dulu).

> **DoD ringkas:** bisa `/engagement` + `/mode`, container hidup, audit jalan, dan **terbukti via tes** perintah ke luar scope diblokir — padahal belum ada satu senjata pun.

---

## 2. Pola OmOP yang Diadopsi (jangan ngarang sendiri)

| Aspek | Pola OmOP yang kita ikuti |
|---|---|
| Skill | Frontmatter `name` / `description`(+`Triggers:`) / `version` / `phase` / `category` / `tools` / `tags`, body = resep bash konkret |
| Nama skill fase | `pentest-mode`, `pentest-recon`, `pentest-enum`, `pentest-exploit`, `pentest-report`, `pentest-workflow` |
| Tool | `tools-catalog.json` deklaratif (schema `ToolEntry`) + `command-builder` yang menyusun perintah dari flags |
| Mode | `ModeConfig` (`scope_enforcement`, `tool_priority`, `skill_chain`, `parallelism`, `stealth`, `report_format`, `safety_constraints`) |
| Command | File `.md`: frontmatter `description:` + `<command-instruction>` yang me-load skill + `<user-request>$ARGUMENTS</user-request>` |
| Arsip skill | 250 SKILL.md OmOP disimpan mentah di `skills-library/`, dipromosikan per-fase |

**Yang bukan pola OmOP & sengaja kita TAMBAH (ini "upgrade"-nya):**
- Hook Claude Code `PreToolUse` yang **menegakkan** `scope_enforcement: strict` (deny-by-default). OmOP menyerahkannya ke kepatuhan agent; kita paksa di mesin.
- Audit log chain-of-custody per engagement.

---

## 3. Prinsip Safety

1. **Deny-by-default.** Target tak cocok `in_scope` eksplisit → blokir. Ragu → blokir.
2. **Fail-closed.** Config engagement hilang/rusak/tak aktif → blokir semua.
3. **Enforcement, bukan imbauan.** `scope_enforcement: strict` di-*enforce* hook, bukan cuma teks prompt.
4. **Auditable.** Tiap keputusan (ALLOW/DENY) tercatat: ts, tool, target, alasan, authorization.

---

## 4. Komponen Fase 0

### 4.1 Struktur repo (gaya OmOP)

```
omop-cc/
├── .claude/
│   ├── settings.json          # daftarkan hook PreToolUse
│   ├── commands/              # /engagement, /mode  (format OmOP)
│   └── skills/                # skill AKTIF (Fase 0: hanya pentest-mode)
├── bin/
│   ├── omop-exec              # jembatan: bangun cmd dari katalog → docker exec
│   └── omop-engagement        # scaffold engagement + set aktif + container up
├── hooks/
│   └── scope-guard.mjs        # enforcement PreToolUse (deny-by-default)
├── src/
│   ├── catalog/               # loader tools-catalog.json (adopsi pola OmOP)
│   └── command-builder/       # bangun perintah dari ToolEntry.flags
├── tools-catalog.json         # registry tool deklaratif (Fase 0: 1 tool uji)
├── skills-library/            # arsip 250 SKILL.md OmOP (referensi)
├── engagements/
│   ├── .active                # pointer engagement aktif
│   └── <name>/
│       ├── scope.yaml         # engagement config (lihat 4.2)
│       ├── audit.log
│       └── output/
├── docker/Dockerfile          # base ramping; tool ditambah per-fase
└── docs/
```

### 4.2 `scope.yaml` — engagement config (bentuk mengikuti `ModeConfig` OmOP)

Satu file per engagement. Menggabungkan mode-config OmOP + daftar target (tambahan kita).

```yaml
engagement: acme-bugbounty
authorization: "HackerOne #12345"      # wajib; dicatat ke audit
mode: bug-bounty                        # auto|ctf|bug-bounty|red-team|blue-team|offensive|grey-hat
scope_enforcement: strict               # strict|moderate|none  (OmOP)
in_scope:
  domains: ["*.acme.com", "api.acme.io"]
  cidrs:   ["203.0.113.0/24"]
out_of_scope:                           # menang atas in_scope
  domains: ["blog.acme.com", "*.corp.acme.com"]
  cidrs:   ["203.0.113.5/32"]
safety_constraints:                     # OmOP SafetyConfig
  block_destructive: true               # blok dump masif / os-shell / write
  block_dos: true                       # blok intensitas bau DoS
rate_limit: 10
notes: "Prod. Jangan sentuh corp."
```

Pencocokan (di hook & `omop-exec`): normalisasi target → cek `out_of_scope` (tolak) → cek `in_scope` (izin) → selain itu tolak.

### 4.3 `tools-catalog.json` (adopsi schema OmOP)

Pakai schema `ToolEntry` OmOP apa adanya (`tools_name`, `category`, `command{base,flags,positional,pipes}`, `installation{linux/darwin/win32}`, `check_installed`, `skills_loader`, `phase[]`, `tags`, `requires_root`, `output_format[]`). **Fase 0** hanya memuat **satu tool uji tak berbahaya** (mis. `curl`) untuk membuktikan pipeline; tool nyata masuk per-fase.

### 4.4 `command-builder` (adopsi pola OmOP)

Menyusun perintah final dari `ToolEntry.command` + flags. Fase 0 cukup versi minimal (cukup untuk tool uji); diperkaya di Fase 1 saat recon tool masuk.

### 4.5 `hooks/scope-guard.mjs` — enforcement (upgrade utama)

Hook `PreToolUse` untuk tool **Bash**, didaftarkan di `.claude/settings.json`. Logika:
1. Muat `engagements/.active` → tak ada → **DENY (fail-closed)**.
2. Muat `scope.yaml` → rusak → **DENY**.
3. `scope_enforcement: none` → lolos (mis. CTF). `strict|moderate` → lanjut.
4. Perintah diawali `omop-exec ` → percayakan pengecekan ke `omop-exec` (jalur sah).
5. Perintah memuat binari jaringan langsung / `docker exec` bukan via `omop-exec` → **DENY** (cegah bypass).
6. Perintah non-jaringan (git/ls/cat/…) → lolos.

`omop-exec` sendiri mengulang cek scope + terapkan `safety_constraints` sebelum `docker exec` (defense-in-depth).

### 4.6 Docker bridge

- `docker/Dockerfile`: base `debian:stable-slim` + hanya alat uji-jembatan (`curl`, `iputils-ping`, `dnsutils`). **Tanpa tool pentest.**
- `bin/omop-exec <toolspec> --target <t>`: cek scope+safety → `docker exec omop-<engagement> <cmd>` (cmd dari command-builder).
- Container persisten per-engagement (dinaikkan oleh `omop-engagement`).

### 4.7 Audit log
`omop-exec` append JSON-per-baris ke `engagements/<t>/audit.log`: `ts, target, tool, decision, reason, authorization`. Timestamp diambil skrip (bukan agent).

### 4.8 Commands (format OmOP)
- `.claude/commands/engagement.md` → load skill `pentest-mode`, tuntun user isi `scope.yaml`, panggil `omop-engagement`.
- `.claude/commands/mode.md` → set `mode` + `scope_enforcement` di engagement aktif.
- Skill aktif Fase 0: **hanya `pentest-mode`** (dipanen dari OmOP, di-tuning ke config kita).

---

## 5. Kriteria Penerimaan (DoD Fase 0)

Semua harus hijau (tes otomatis, target uji = domain contoh/loopback, tanpa jaringan nyata):

| # | Tes | Harapan |
|---|---|---|
| T1 | `omop-exec curl --target api.acme.io` (in_scope) | ALLOW, ter-exec di container, audit ALLOW |
| T2 | `omop-exec curl --target evil.com` (luar scope) | DENY, audit `deny-by-default` |
| T3 | `omop-exec curl --target blog.acme.com` (out_of_scope) | DENY (pengecualian menang) |
| T4 | Agent `curl https://evil.com` langsung (bypass) | Hook DENY, tak jalan |
| T5 | Agent `docker exec omop-acme curl evil.com` (bypass) | Hook DENY |
| T6 | Tanpa engagement aktif | Fail-closed, DENY |
| T7 | `scope.yaml` rusak/hilang | Fail-closed, DENY |
| T8 | `safety_constraints.block_destructive` aktif + aksi destruktif | DENY; kalau `none`/lab → ALLOW |
| T9 | `scope_enforcement: none` (mode CTF) | perintah lolos |
| T10 | `/engagement` + `/mode` bikin struktur + container hidup + `.active` benar | lengkap |
| T11 | Audit log memuat ts/target/tool/decision/reason/authorization | lengkap |
| T12 | `tools-catalog.json` tervalidasi schema + loader baca tool uji | OK |

---

## 6. Ditunda
- Katalog `safety_constraints` lengkap → per-fase saat tool masuk.
- `command-builder` penuh (banyak flag) → Fase 1.
- Auto-detect mode dari target → Fase 6.
- (Opsional) egress-lock jaringan container sebagai hardening ekstra → Fase 6/7, **bukan** Fase 0 (di luar pola OmOP).

---

## 7. Risiko & Mitigasi
| Risiko | Mitigasi |
|---|---|
| Agent temukan bypass tak terduga | Choke point `omop-exec` + hook deny-by-default seluruh binari jaringan + audit |
| `--target` menyesatkan (arg nembak host lain) | Diterima sebagai batas Fase 0 (jaminan = no-bypass + target jujur); egress-lock jaringan = hardening Fase 6/7 bila diperlukan |
| Wildcard scope kelewat longgar | Validasi `scope.yaml`: tolak wildcard TLD-level |
| Fail-open karena bug | Semua jalur error → fail-closed (DENY) |
