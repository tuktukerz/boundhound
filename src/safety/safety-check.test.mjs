// src/safety/safety-check.test.mjs
import { test, expect } from "bun:test"
import { checkSafety } from "./safety-check.mjs"

const strict = { block_destructive: true, block_dos: true }
const off = { block_destructive: false, block_dos: false }

test("blocks destructive flag when block_destructive on", () => {
  const r = checkSafety("sqlmap", ["-u", "x", "--dump-all"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/destructive/)
})

test("blocks os-shell", () => {
  expect(checkSafety("sqlmap", ["--os-shell"], strict).decision).toBe("DENY")
})

test("blocks DoS-ish extreme threads when block_dos on", () => {
  expect(checkSafety("ffuf", ["-t", "5000"], strict).decision).toBe("DENY")
})

test("allows benign args", () => {
  expect(checkSafety("curl", ["-I"], strict).decision).toBe("ALLOW")
})

test("lab profile (all off) allows destructive", () => {
  expect(checkSafety("sqlmap", ["--dump-all"], off).decision).toBe("ALLOW")
})

test("DOS check catches --threads=<n> form", () => {
  expect(checkSafety("ffuf", ["--threads=5000"], strict).decision).toBe("DENY")
})

test("DOS check catches -t<n> glued form", () => {
  expect(checkSafety("ffuf", ["-t5000"], strict).decision).toBe("DENY")
})

test("blocks destructive flag case-insensitive", () => {
  expect(checkSafety("sqlmap", ["--DUMP-ALL"], strict).decision).toBe("DENY")
})

test("checkSafety treats null constraints as strict (deny-by-default)", () => {
  expect(checkSafety("sqlmap", ["--os-shell"], null).decision).toBe("DENY")
})

test("checkSafety treats undefined constraints as strict", () => {
  expect(checkSafety("sqlmap", ["--os-shell"], undefined).decision).toBe("DENY")
})

// Task 3: nmap-shaped DoS guards (spec §2.3). The flag=value/spaced-value
// numeric checks below are case-insensitive; the -T5 literal deny (T3a) is
// the exception — it is case-SENSITIVE by design (see the DOS_LITERAL
// comment in safety-check.mjs: uppercase -T5 is nmap's timing template,
// lowercase -t/-t5 is the unrelated threads flag).

test("T3a: blocks nmap -T5 (insane timing) when block_dos on", () => {
  const r = checkSafety("nmap", ["-T5"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T3b: allows nmap -T4 (normal timing)", () => {
  expect(checkSafety("nmap", ["-T4"], strict).decision).toBe("ALLOW")
})

test("T3c: blocks nmap --min-rate above cap (spaced form)", () => {
  const r = checkSafety("nmap", ["--min-rate", "100000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T3d: blocks nmap --min-rate above cap (=value form)", () => {
  const r = checkSafety("nmap", ["--min-rate=100000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T3e: allows nmap --min-rate under cap", () => {
  expect(checkSafety("nmap", ["--min-rate", "100"], strict).decision).toBe("ALLOW")
})

test("T3e2: blocks nmap --max-rate above cap (spaced form)", () => {
  const r = checkSafety("nmap", ["--max-rate", "100000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T3e3: blocks nmap --max-rate above cap (=value form)", () => {
  const r = checkSafety("nmap", ["--max-rate=100000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T3f: allows -p (port spec) - not a DoS flag", () => {
  expect(checkSafety("nmap", ["-p", "1-1000"], strict).decision).toBe("ALLOW")
})

test("T3g: existing -t 5000 still DENYs (regression)", () => {
  expect(checkSafety("ffuf", ["-t", "5000"], strict).decision).toBe("DENY")
})

test("T3h: lowercase -t5 (glued, 5 threads) ALLOWs - -T5 deny is case-sensitive, not confused with threads flag", () => {
  const r = checkSafety("ffuf", ["-t5"], strict)
  expect(r.decision).toBe("ALLOW")
  expect(r.reason).toBe("safety-ok")
})

// Task 1 (Phase 2 enum, spec §2.2): nuclei-shaped DoS guards — concurrency
// and rate-limit caps. Same spaced + =value handling as the existing DOS
// array; no glued form needed for these (long-flag-only in practice).

test("T1a: blocks nuclei -c above cap (spaced form)", () => {
  const r = checkSafety("nuclei", ["-c", "100"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T1b: allows nuclei -c under cap", () => {
  expect(checkSafety("nuclei", ["-c", "25"], strict).decision).toBe("ALLOW")
})

test("T1c: blocks nuclei -concurrency above cap (spaced form)", () => {
  const r = checkSafety("nuclei", ["-concurrency", "100"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T1d: blocks nuclei -rl above cap (spaced form)", () => {
  const r = checkSafety("nuclei", ["-rl", "5000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T1e: blocks nuclei -rl above cap (=value form)", () => {
  const r = checkSafety("nuclei", ["-rl=5000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("T1f: allows nuclei -rl under cap", () => {
  expect(checkSafety("nuclei", ["-rl", "150"], strict).decision).toBe("ALLOW")
})

test("T1g: existing -t 5000 still DENYs (regression, unrelated to nuclei caps)", () => {
  expect(checkSafety("ffuf", ["-t", "5000"], strict).decision).toBe("DENY")
})

test("T1h: nuclei -t <template path> (non-numeric) is not denied by the -t numeric cap", () => {
  const r = checkSafety("nuclei", ["-t", "/templates/x.yaml"], strict)
  expect(r.decision).toBe("ALLOW")
  expect(r.reason).toBe("safety-ok")
})

// Fix-wave FIX 1 (Critical): ffuf's real rate flag is single-dash "-rate",
// not "--rate" -- the pre-existing DOS array only capped the double-dash
// form, so "-rate <huge>" sailed through uncapped. Same spaced / =value
// handling as every other DOS rule in the file.

test("F1a: blocks ffuf -rate above cap (spaced form)", () => {
  const r = checkSafety("ffuf", ["-rate", "5000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("F1b: blocks ffuf -rate above cap (=value form)", () => {
  const r = checkSafety("ffuf", ["-rate=5000"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("F1c: allows ffuf -rate under cap", () => {
  expect(checkSafety("ffuf", ["-rate", "500"], strict).decision).toBe("ALLOW")
})

// Boundary tests for the Phase-2 nuclei caps (-c max 50, -rl max 1000) --
// cheap quality win, pins the exact off-by-one edges.

test("F1d: nuclei -c at the cap (50) ALLOWs", () => {
  expect(checkSafety("nuclei", ["-c", "50"], strict).decision).toBe("ALLOW")
})

test("F1e: nuclei -c one over the cap (51) DENYs", () => {
  const r = checkSafety("nuclei", ["-c", "51"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("F1f: nuclei -rl at the cap (1000) ALLOWs", () => {
  expect(checkSafety("nuclei", ["-rl", "1000"], strict).decision).toBe("ALLOW")
})

test("F1g: nuclei -rl one over the cap (1001) DENYs", () => {
  const r = checkSafety("nuclei", ["-rl", "1001"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

// Task 1 (Phase 3 exploit, spec §2.2): sqlmap weaponizing-flag denials +
// --level/--risk caps. THE safety centerpiece for the exploit phase.
// block_destructive must deny every flag that would turn a proof-of-vuln
// SQLi confirmation into data exfiltration, RCE, file/registry access,
// privilege escalation, or arbitrary code execution.

const WEAPONIZING_FLAGS = [
  "--dump", "--dump-all", "--os-shell", "--os-pwn", "--os-cmd",
  "--sql-shell", "--sql-query", "--file-read", "--file-write", "--file-dest",
  "--reg-read", "--reg-add", "--reg-del", "--priv-esc", "--msf-path",
  "--os-smbrelay", "--eval", "--os-bof",
]

for (const flag of WEAPONIZING_FLAGS) {
  test(`X1: sqlmap ${flag} is DENIED (destructive)`, () => {
    const r = checkSafety("sqlmap", ["-u", "http://x/?id=1", flag], strict)
    expect(r.decision).toBe("DENY")
    expect(r.reason).toMatch(/destructive/i)
  })
}

test("X1: sqlmap --dump=1 (=value form) is DENIED", () => {
  const r = checkSafety("sqlmap", ["-u", "http://x/?id=1", "--dump=1"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/destructive/i)
})

const BENIGN_PROOF_FLAGS = ["--batch", "--dbs", "--current-db", "--banner", "--is-dba", "--current-user"]

for (const flag of BENIGN_PROOF_FLAGS) {
  test(`X1: sqlmap ${flag} is ALLOWED (non-destructive proof flag)`, () => {
    const r = checkSafety("sqlmap", ["-u", "http://x/?id=1", flag], strict)
    expect(r.decision).toBe("ALLOW")
  })
}

test("X1: sqlmap --dbms mysql is ALLOWED - not mistaken for --dump", () => {
  const r = checkSafety("sqlmap", ["-u", "http://x/?id=1", "--dbms", "mysql"], strict)
  expect(r.decision).toBe("ALLOW")
})

test("X1: sqlmap --dbs is ALLOWED - not mistaken for --dump (substring guard)", () => {
  const r = checkSafety("sqlmap", ["-u", "http://x/?id=1", "--dbs"], strict)
  expect(r.decision).toBe("ALLOW")
})

test("X2: sqlmap --level 5 is DENIED (spaced form, above cap)", () => {
  const r = checkSafety("sqlmap", ["--level", "5"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("X2: sqlmap --level=5 is DENIED (=value form, above cap)", () => {
  const r = checkSafety("sqlmap", ["--level=5"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("X2: sqlmap --level 3 is ALLOWED (at cap)", () => {
  expect(checkSafety("sqlmap", ["--level", "3"], strict).decision).toBe("ALLOW")
})

test("X2: sqlmap --risk 3 is DENIED (spaced form, above cap)", () => {
  const r = checkSafety("sqlmap", ["--risk", "3"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("X2: sqlmap --risk=3 is DENIED (=value form, above cap)", () => {
  const r = checkSafety("sqlmap", ["--risk=3"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/dos:/i)
})

test("X2: sqlmap --risk 2 is ALLOWED (at cap)", () => {
  expect(checkSafety("sqlmap", ["--risk", "2"], strict).decision).toBe("ALLOW")
})

test("X2: existing --threads cap still enforced (regression, not weakened by new flags)", () => {
  expect(checkSafety("sqlmap", ["--threads", "5000"], strict).decision).toBe("DENY")
})

test("X2: existing --dump-all destructive rule still enforced (regression, not weakened)", () => {
  expect(checkSafety("sqlmap", ["--dump-all"], strict).decision).toBe("DENY")
})
