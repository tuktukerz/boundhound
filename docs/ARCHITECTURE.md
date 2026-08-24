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
| Skill playbook (recon, xss, sqli, dst) | Frontmatter OmOP + `.claude/skills/*/SKILL.md` (aktif) + `skills-library/` (arsip 250) |
| Registry tool | `tools-catalog.json` (schema `ToolEntry` OmOP) + `command-builder` |
| Eksekusi tool (nmap, nuclei, sqlmap) | `bin/omop-exec` → `docker exec` ke container Linux |
| Tool via MCP (mis. Burp Suite) | MCP server native Claude Code (on-pattern; OmOP juga pakai MCP) — lihat §7 |
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
│   ├── settings.json        # daftarkan hook PreToolUse (scope-guard)
│   ├── commands/            # /engagement, /mode, ... (format OmOP)
│   └── skills/              # skill AKTIF (dipromosikan per-fase)
├── bin/
│   ├── omop-exec            # bangun cmd dari katalog → scope+safety → docker exec
│   └── omop-engagement      # scaffold engagement + set aktif + container up
├── hooks/
│   └── scope-guard.mjs      # enforcement PreToolUse; cegah bypass omop-exec
├── src/
│   ├── catalog/             # loader tools-catalog.json (pola OmOP)
│   └── command-builder/     # bangun perintah dari ToolEntry.flags
├── tools-catalog.json       # registry tool deklaratif (schema ToolEntry)
├── docker/Dockerfile        # base ramping; tool ditambah per-fase
├── skills-library/          # arsip 250 skill OmOP (referensi, tidak di-load)
├── engagements/
│   ├── .active              # pointer ke engagement aktif
│   └── <target>/
│       ├── scope.yaml       # engagement config: mode + scope + safety_constraints
│       ├── audit.log        # chain-of-custody tiap perintah
│       └── output/          # hasil per fase
└── docs/
    ├── ARCHITECTURE.md      # dokumen ini
    └── specs/               # spec detail per fase
```

## 7. Integrasi MCP (mis. Burp Suite)

Claude Code mendukung MCP server native, dan OmOP juga dibangun di atas MCP — jadi menambah tool lewat MCP itu **on-pattern**. **Burp Suite** punya MCP server resmi yang cocok banget untuk web/bug-bounty (Proxy, Repeater, Scanner). Rencana penempatan: **Fase 2–3 (enum/exploit)**, BUKAN Fase 0.

Catatan penting saat dipakai:
- Butuh Burp jalan (Burp **Pro** untuk active scan; Community terbatas). Burp jalan di **host**, bukan di container tool.
- **Safety:** hook scope-guard kita hanya melihat perintah Bash — dia **tidak** melihat tiap request yang dikirim Burp. Jadi scope untuk Burp **wajib diset juga di Target Scope Burp**; panggilan MCP Burp diperlakukan sebagai choke point terpisah.

*(Di Fase 0 hanya sebagian yang dibangun — lihat spec Fase 0.)*
