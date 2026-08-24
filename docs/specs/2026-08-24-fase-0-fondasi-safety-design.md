# Spec Desain — Fase 0: Fondasi & Safety

**Tanggal:** 2026-08-24
**Status:** draft, menunggu review
**Prasyarat:** tidak ada (ini fase pertama)
**Menghasilkan:** fondasi safety yang wajib lulus tes sebelum fase kemampuan apa pun dibangun.

---

## 1. Tujuan & Non-Tujuan

### Tujuan
Membangun **lapisan keamanan yang membuktikan** bahwa agent **tidak bisa** menyentuh target di luar scope — baik lewat jalur resmi maupun dengan menghindar. Plus infrastruktur pendukung minimum: container tool, audit log, dan cara memulai engagement.

### Non-Tujuan (TEGAS)
- ❌ **Tidak ada kemampuan serang/recon apa pun.** Nol tool pentest (nmap/nuclei/dst). Itu Fase 1+.
- ❌ Tidak ada orchestrator, tidak ada `/fullscan`, tidak ada skill dipromosikan.
- ❌ Tidak ada mode detection, tidak ada report.

> Fase 0 sukses kalau: kita bisa mulai engagement, container hidup, audit jalan, dan **terbukti secara tes** bahwa perintah ke target luar-scope diblokir — sementara belum ada satu pun senjata terpasang.

---

## 2. Prinsip Desain

1. **Deny-by-default.** Kalau target tidak cocok `in_scope` secara eksplisit → blokir. Ragu = blokir.
2. **Fail-closed.** `scope.yaml` hilang/rusak/tak ada engagement aktif → blokir semua, jangan lolos.
3. **Choke point tunggal.** Semua eksekusi tool jaringan lewat SATU pintu (`omop-run`). Satu tempat yang di-review, di-audit, di-tes.
4. **Defense-in-depth.** `omop-run` melakukan pengecekan sebenarnya; **hook** mencegah agent menghindari `omop-run`. Dua lapis independen.
5. **Auditable.** Tiap keputusan (izin/tolak) tercatat dengan timestamp, tool, target, alasan.

---

## 3. Komponen (unit-unit terisolasi)

Tiap unit: satu tujuan, antarmuka jelas, bisa dites sendiri.

### 3.1 `scope.yaml` — deklarasi scope

Satu file per engagement. **Sumber kebenaran** untuk "apa yang boleh disentuh".

```yaml
# engagements/<target>/scope.yaml
engagement: acme-bugbounty          # nama/label
authorization: "HackerOne #12345"   # bukti izin (wajib diisi, dicatat ke audit)
in_scope:
  domains:
    - "*.acme.com"                  # wildcard didukung
    - "api.acme.io"
  cidrs:
    - "203.0.113.0/24"
out_of_scope:                        # pengecualian eksplisit; menang atas in_scope
  domains:
    - "blog.acme.com"
    - "*.corp.acme.com"
  cidrs:
    - "203.0.113.5/32"
rate_limit: 10                       # req/detik (dipakai fase nanti; dicatat sekarang)
safety_profile: default             # default | lab (lab membuka aksi destruktif)
notes: "Prod. Jangan sentuh subdomain corp."
```

**Aturan pencocokan (di `omop-run`):**
1. Normalisasi target (URL → host; strip port/scheme).
2. Kalau cocok `out_of_scope` → **TOLAK** (pengecualian menang).
3. Kalau cocok `in_scope` (domain exact / wildcard / IP dalam CIDR) → **IZIN**.
4. Selain itu → **TOLAK** (deny-by-default).

### 3.2 `bin/omop-run` — choke point eksekusi

Satu-satunya jalan sah menjalankan tool. Antarmuka:

```
omop-run --target <host|url|ip> -- <tool> [args...]
```

Alur:
1. Baca `engagements/.active` → tak ada → **fail-closed** (exit 3).
2. Muat & validasi `scope.yaml` → rusak → **fail-closed** (exit 3).
3. Cek `--target` lawan scope (§3.1) → tolak → log + exit 2.
4. Terapkan **safety profile** (§3.3) ke `<tool> args` → aksi terlarang → log + exit 2.
5. Tulis baris audit (§3.4).
6. Eksekusi: `docker exec <container-engagement> <tool> args`.

> Catatan: `--target` wajib eksplisit. Kita **tidak** menebak target dari parsing arg tool yang sembarangan — target dinyatakan terpisah supaya pengecekan deterministik.

### 3.3 Safety Profile — blok aksi destruktif/DoS

Daftar aturan (profil `default`) yang **memblokir** by default; profil `lab` melewatinya.

Contoh aturan (final list disepakati di implementasi):
- Blok flag dump masif / write (mis. `sqlmap --dump-all`, `--os-shell`) di profil default.
- Blok intensitas berlebih yang bau DoS (mis. thread/rate ekstrem).
- Blok tool yang murni destruktif.

Di Fase 0 kerangkanya dibangun + minimal 1 aturan uji; katalog penuh diperkaya seiring tool masuk per fase.

### 3.4 Audit log — chain-of-custody

`omop-run` append ke `engagements/<t>/audit.log` (JSON per baris):

```json
{"ts":"2026-08-24T04:10:00Z","target":"api.acme.io","tool":"curl","decision":"ALLOW","reason":"in_scope:api.acme.io","authorization":"HackerOne #12345"}
{"ts":"2026-08-24T04:10:05Z","target":"evil.com","tool":"curl","decision":"DENY","reason":"deny-by-default"}
```

> Timestamp diambil di dalam skrip (bukan oleh agent) supaya jujur.

### 3.5 `hooks/scope-guard.sh` — pencegah bypass (lapis ke-2)

Didaftarkan sebagai hook `PreToolUse` untuk tool **Bash** di `.claude/settings.json`. Menerima command yang akan dijalankan, lalu:
- **IZIN** kalau command diawali `omop-run ` (jalur sah) atau jelas non-jaringan (git, ls, cat, dst).
- **TOLAK** kalau command memuat binari jaringan langsung (curl/wget/nc/nmap/…) atau `docker exec …` yang **bukan** lewat `omop-run`.

Ini menutup celah "agent nembak langsung tanpa lewat choke point". `omop-run` = kebenaran; hook = pagar keliling.

### 3.6 Docker foundation

- `docker/Dockerfile`: base ramping (mis. `debian:stable-slim`). Fase 0 **hanya** memasang alat uji-jembatan yang tidak berbahaya (mis. `curl`, `iputils-ping`, `dnsutils`) untuk membuktikan scope-check bekerja. **Tidak ada tool pentest.**
- `bin/omop-container`: `up` (jalankan container persisten `omop-<engagement>` detached), `down`, `status`.

### 3.7 `bin/omop-engagement` + `/engagement` command

- `bin/omop-engagement <nama>`: buat `engagements/<nama>/` dari template `scope.yaml`, set `engagements/.active`, panggil `omop-container up`.
- `.claude/commands/engagement.md`: slash command yang menuntun agent memandu user mengisi scope lalu memanggil skrip di atas.

---

## 4. Alur Data

```
User: /engagement acme
  └─ omop-engagement acme → tulis scope.yaml (user isi) → set .active → omop-container up
User (atau agent): omop-run --target api.acme.io -- curl -I https://api.acme.io
  └─ scope-guard hook: diawali "omop-run" → IZIN lewat
  └─ omop-run: baca .active → validasi scope.yaml → cek target (in_scope) → safety check → audit ALLOW → docker exec
Agent nakal: curl https://evil.com   (bypass)
  └─ scope-guard hook: binari jaringan langsung, bukan omop-run → TOLAK (command tak pernah jalan)
```

---

## 5. Kriteria Penerimaan (Definition of Done Fase 0)

Fase 0 **selesai** hanya jika semua tes ini hijau:

| # | Tes | Harapan |
|---|---|---|
| T1 | `omop-run --target api.acme.io -- curl` (in_scope) | IZIN, ter-exec di container, audit `ALLOW` |
| T2 | `omop-run --target evil.com -- curl` (luar scope) | TOLAK, exit 2, audit `DENY:deny-by-default` |
| T3 | `omop-run --target blog.acme.com -- curl` (out_of_scope eksplisit) | TOLAK (pengecualian menang) |
| T4 | Agent coba `curl https://evil.com` langsung (bypass) | Hook TOLAK, command tak jalan |
| T5 | Agent coba `docker exec omop-acme curl evil.com` (bypass) | Hook TOLAK |
| T6 | `omop-run …` tanpa engagement aktif | Fail-closed, exit 3 |
| T7 | `scope.yaml` rusak/hilang | Fail-closed, TOLAK semua |
| T8 | Aksi safety-profile terlarang (min. 1 aturan) di profil default | TOLAK; di profil `lab` → IZIN |
| T9 | `/engagement` bikin struktur + container hidup + `.active` benar | Semua ada |
| T10 | Audit log memuat ts, target, tool, decision, reason, authorization | Lengkap & benar |

**Cara pembuktian:** semua tes ditulis sebagai skrip otomatis (bash test harness) yang jalan tanpa menyentuh jaringan nyata (target uji = domain contoh/loopback). Tidak ada "percaya saja" — harus ada output tes hijau.

---

## 6. Yang Ditunda

- Katalog safety-profile lengkap → diperkaya per fase saat tool masuk.
- Pembatasan scope di **layer jaringan** container (mis. firewall egress) → hardening opsional Fase 6/7.
- Rate limiting aktif → dipakai mulai Fase 1.

---

## 7. Risiko & Mitigasi

| Risiko | Mitigasi |
|---|---|
| Agent temukan cara bypass yang tak terpikir | Choke point sempit + hook deny-by-default untuk seluruh binari jaringan; audit tiap perintah |
| `--target` diisi salah/menyesatkan oleh agent | Target dicocokkan ketat ke scope; kalau host asli command ≠ `--target`, itu tetap dibatasi oleh scope container + audit (dicatat sebagai catatan hardening Fase 1) |
| Wildcard scope kelewat longgar (`*.com`) | Validasi `scope.yaml`: tolak wildcard TLD-level saat parsing |
| Fail-open karena bug parsing | Semua jalur error → fail-closed (default TOLAK) |
