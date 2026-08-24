# OmOP-CC — Arsitektur & Roadmap

**Autonomous Pentest Agent di atas Claude Code.**
Terinspirasi & memanen skill dari [`zakirkun/oh-my-open-pentest`](https://github.com/zakirkun/oh-my-open-pentest) (OmOP), tapi dibangun ulang sebagai native Claude Code — bukan plugin OpenCode.

> Status: **Fase 0 — perencanaan.** Belum ada kode implementasi. Dokumen ini + `docs/specs/` adalah satu-satunya artefak sejauh ini.

---

## 1. Kenapa dibangun ulang, bukan fork

OmOP terikat ke OpenCode (entry point-nya plugin OpenCode; tidak ada edisi Claude Code). Yang berharga & portable dari OmOP adalah **250 `SKILL.md`** — markdown playbook murni. Yang tidak kita bawa adalah plumbing OpenCode-nya (tool runner, orchestrator, config).

**Keputusan (Opsi B):** perlakukan OmOP sebagai **tambang bahan baku + acuan**. Panen skill-nya, bangun orchestrator + safety layer versi kita sendiri di atas primitives Claude Code.

---

## 2. Definisi Sukses v1

> Di satu target **berizin**, **satu perintah** menjalankan **recon → enum → verify → report**, menghasilkan **laporan yang layak di-submit**, dengan **NOL pelanggaran scope**.

Dua metrik yang tidak bisa ditawar: **(1)** output = report yang beneran kepakai, **(2)** nol request keluar dari scope.

---

## 3. Pemetaan ke Primitives Claude Code

| Konsep pentest agent | Diwujudkan pakai |
|---|---|
| Skill playbook (recon, xss, sqli, dst) | `.claude/skills/*/SKILL.md` (aktif) + `skills-library/` (arsip 250) |
| Eksekusi tool (nmap, nuclei, sqlmap) | Wrapper tunggal `omop-run` → `docker exec` ke container Linux |
| Orchestrator (recon→…→report) | Master skill yang menyetir **subagents** per fase |
| `/engagement`, `/fullscan` | `.claude/commands/*.md` |
| Engagement mode | Skill / argumen command |
| **Scope enforcement** | **Hook** `PreToolUse` di `.claude/settings.json` + choke point `omop-run` |
| Safety profile (anti-destruktif/DoS) | Aturan di `omop-run` |
| Verification layer | Subagent "verify" khusus |
| Report | Skill "report" (CVSS, PoC, repro) |
| Chain-of-custody / audit | `omop-run` menulis `engagements/<t>/audit.log` |

---

## 4. Keputusan Terkunci (hasil grilling)

| # | Keputusan | Nilai |
|---|---|---|
| Arah | Bangun sendiri; OmOP = tambang skill + acuan | Opsi B |
| Tujuan | Belajar + kerjaan beneran + portfolio | bar "kerjaan beneran" |
| Legal | Engagement resmi + bug bounty + lab sendiri | (a)+(b)+(c) |
| Platform | Claude Code | fixed |
| Runtime tool | Container Docker Linux, Dockerfile custom ramping, persisten per-engagement | Q4=b, Q15=b |
| Jembatan | Claude Code di Mac → `docker exec` | Q11=a |
| Otonomi | Full-auto **sampai exploit**, DI DALAM 2 pagar wajib | Q6=a |
| Pagar 1 | Scope hook keras, **deny-by-default** | wajib |
| Pagar 2 | Safety profile — blok aksi destruktif/DoS by default | wajib |
| Scope | `scope.yaml` per engagement | Q9 |
| Skill | Panen 250 → `skills-library/`, promosi per-fase + tuning | Q3, Q12=b |
| Model | Campur per-fase (cepat buat recon/enum, Opus buat exploit/verify/report) | Q10=b |
| Lokasi | Repo git baru `~/Documents/ian/omop-cc` | Q13 |
| Urutan | **Fase 0 (safety) duluan**, wajib | Q14 |

---

## 5. Peta Fase

Tiap fase = milestone berdiri sendiri dengan siklus **spec → plan → implement** sendiri.

| Fase | Nama | Output milestone | Status |
|---|---|---|---|
| **0** | **Fondasi & Safety** | Scope enforcement + Docker bridge + audit + `/engagement`. Terbukti mustahil nyentuh target luar-scope. **Nol kemampuan serang.** | 📝 spec ditulis |
| 1 | Recon | Peta attack surface terstruktur (subdomain, host, port, tech) | ⏳ |
| 2 | Enumeration | Temuan mentah (vuln nuclei, endpoint, param) dari output Fase 1 | ⏳ |
| 3 | Exploitation | Konfirmasi eksploitasi (full-auto di dalam pagar) | ⏳ |
| 4 | Verification | Tiap finding dikonfirmasi ulang; false-positive dibuang | ⏳ |
| 5 | Reporting | Report (CVSS, PoC, repro) — format HackerOne/teknis | ⏳ |
| 6 | Orchestrator | `/fullscan` merangkai semua fase otonom + deteksi mode | ⏳ |
| 7 | Ekspansi | Domain lain: network/AD, mobile, CTF; intelligence layer | ⏳ |

**Prinsip:** *safety sebelum kemampuan.* Tidak ada satu tool serang pun sebelum Fase 0 lulus tes.

---

## 6. Struktur Repo (target akhir)

```
omop-cc/
├── .claude/
│   ├── settings.json        # hook PreToolUse (scope-guard)
│   ├── commands/            # /engagement, /fullscan, ...
│   └── skills/              # skill AKTIF (dipromosikan per-fase)
├── bin/
│   ├── omop-run             # choke point: scope-check → safety → docker exec
│   ├── omop-engagement      # scaffold engagement baru + set aktif
│   └── omop-container        # lifecycle container (up/down/status)
├── hooks/
│   └── scope-guard.sh       # dipanggil settings.json; cegah bypass omop-run
├── docker/
│   └── Dockerfile           # base ramping; tool ditambah per-fase
├── skills-library/          # arsip 250 skill OmOP (referensi, tidak di-load)
├── engagements/
│   ├── .active              # pointer ke engagement aktif
│   └── <target>/
│       ├── scope.yaml       # in_scope / out_of_scope / rate_limit
│       ├── audit.log        # chain-of-custody tiap perintah
│       └── output/          # hasil per fase
└── docs/
    ├── ARCHITECTURE.md      # dokumen ini
    └── specs/               # spec detail per fase
```

*(Di Fase 0 hanya sebagian yang dibangun — lihat spec Fase 0.)*
