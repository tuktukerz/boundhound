// test/verify-skill.test.mjs
//
// Phase 4 verify (Task 3): the pentest-verify skill orchestrates
// bh-findings -> re-check each unverified candidate finding via bh-exec
// (SAME bounded flags that produced it, never a heavier check) ->
// bh-findings again, so findings.json reflects verified reality. The
// /verify command loads + follows it. This is a STATIC structural check —
// it reads SKILL.md/verify.md as text and asserts on their shape/content,
// mirroring test/enum-skill.test.mjs and test/exploit-skill.test.mjs. It
// does not invoke bh-exec/bh-findings or any real tool (those have their
// own suites: bin/bh-findings.test.mjs, src/verify/findings.test.mjs).
//
// SAFETY (spec §4/§5): re-verification only ever re-runs the SAME bounded
// check that produced a finding, via bh-exec, using ONLY already-cataloged
// flags — never a heavier scan, and never sqlmap at all (a sqli finding is
// already confirmed by exploit; re-running it here would be pointless and,
// if it ever were reworded to happen, would risk re-introducing an
// escalation path this phase must never open). A finding that no longer
// reproduces must be KEPT and flagged verified:false, never silently
// dropped. This suite's SAFETY section (below "Using this skill") asserts
// both: no sqlmap invocation anywhere in this skill, and every real
// nuclei/httpx/nmap invocation uses only the exact flags already declared
// for that tool in tools-catalog.json.
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(import.meta.dir, "..")
const skillPath = join(repoRoot, ".claude", "skills", "pentest-verify", "SKILL.md")
const verifyCmdPath = join(repoRoot, ".claude", "commands", "verify.md")

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a skill/command markdown file and parses it as YAML.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

test("pentest-verify/SKILL.md exists and has a name field", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-verify")
})

test("pentest-verify/SKILL.md has a non-empty description", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("pentest-verify/SKILL.md description declares triggers", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.description).toMatch(/Triggers:/)
})

test("pentest-verify/SKILL.md phase includes verify", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("verify")
})

test("pentest-verify/SKILL.md category includes verify", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.category)).toBe(true)
  expect(fm.category).toContain("verify")
})

test("pentest-verify/SKILL.md tools list nuclei, httpx, and nmap", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.tools)).toBe(true)
  expect(fm.tools).toContain("nuclei")
  expect(fm.tools).toContain("httpx")
  expect(fm.tools).toContain("nmap")
})

// --- positive routing: every re-check tool actually goes through bh-exec ---

test("pentest-verify/SKILL.md routes every re-check tool exclusively via bh-exec (positive routing check)", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-exec/)
  // Both the plugin-mode form (quoted path, e.g. `.../bh-exec.mjs" nuclei
  // --target`) and the dev-mode form (`bin/bh-exec.mjs nuclei --target`)
  // match this. A bare negative check would be near-vacuous — assert the
  // real routing exists, same discipline as test/enum-skill.test.mjs.
  for (const tool of ["nuclei", "httpx", "nmap"]) {
    expect(text).toMatch(new RegExp(`bh-exec\\.mjs"?\\s+${tool}\\s+--target`))
  }
})

test("pentest-verify/SKILL.md documents the bh-findings step twice: build candidates, then rebuild after re-checking", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-findings/)
  expect(text).toMatch(/findings\.json/)
})

test("pentest-verify/SKILL.md requires an active engagement, scope, and at least one prior-phase map, and says to run earlier phases if missing", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/active engagement/i)
  expect(text).toMatch(/\bscope\b/i)
  expect(text).toMatch(/recon-map\.json/)
  expect(text).toMatch(/enum-map\.json/)
  expect(text).toMatch(/exploit-map\.json/)
  expect(text).toMatch(/\/recon\b/)
  expect(text).toMatch(/\/enum\b/)
  expect(text).toMatch(/\/exploit\b/)
  expect(text).toMatch(/\brefuse\b/i)
})

test("pentest-verify/SKILL.md documents the output/verify/recheck layout", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/output\/verify\/recheck/)
})

test("pentest-verify/SKILL.md documents re-check outputs by exact extension per tool", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\.jsonl/)
  expect(text).toMatch(/\.httpx\.jsonl/)
  expect(text).toMatch(/\.gnmap/)
})

// --- SAFETY: the load-bearing assertions for this skill ---

test("pentest-verify/SKILL.md states re-verification never escalates: SAME bounded check, no heavier scan", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/never escalat/i)
  expect(text).toMatch(/same bounded/i)
})

test("pentest-verify/SKILL.md states a non-reproducing finding is kept and flagged, never silently dropped", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/verified:\s*false/)
  expect(text).toMatch(/\b(kept|keeps|keep)\b/i)
  expect(text).toMatch(/not\s+(silently\s+)?dropp?ed|never\s+dropp?ed/i)
})

test("pentest-verify/SKILL.md states sqli findings are already confirmed and sqlmap is never re-run here", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/sqlmap/i)
  expect(text).toMatch(/already confirmed/i)
  expect(text).toMatch(/do not re-run|never re-run|not re-run/i)
})

test("pentest-verify/SKILL.md never instructs a real sqlmap invocation via bh-exec", () => {
  const text = readFileSync(skillPath, "utf8")
  // sqlmap is discussed in prose (it must be, per the test above) but this
  // skill must never actually hand the operator a `bh-exec ... sqlmap
  // --target` command line, and certainly never one carrying a
  // data-exfiltration or shell flag.
  expect(text).not.toMatch(/bh-exec\.mjs"?\s+sqlmap\s+--target/)
  expect(text).not.toMatch(/sqlmap[^\n]*--dump/i)
  expect(text).not.toMatch(/sqlmap[^\n]*--os-shell/i)
})

// Every declared/bounded flag from tools-catalog.json (Task 2) for each
// re-check tool — the ONLY flags a real invocation in this skill may use,
// beyond bh-exec's own --target/--data-dir.
const BOUNDED_FLAGS = {
  nuclei: ["-t", "-severity", "-c", "-rl", "-jsonl", "-silent", "-disable-update-check", "--target", "--data-dir"],
  httpx: ["-silent", "-json", "-td", "-title", "-sc", "--target", "--data-dir"],
  nmap: ["-sT", "-sV", "-Pn", "-T3", "-T4", "-p", "-oG", "--target", "--data-dir"],
}

function extractInvocationBlocks(text, tool) {
  const blocks = []
  const fenceRe = /```[a-z]*\n([\s\S]*?)```/g
  let m
  while ((m = fenceRe.exec(text))) {
    if (new RegExp(`bh-exec\\.mjs"?\\s+${tool}\\s+--target`).test(m[1])) blocks.push(m[1])
  }
  return blocks
}

for (const tool of ["nuclei", "httpx", "nmap"]) {
  test(`pentest-verify/SKILL.md has at least one real ${tool} re-check invocation code block`, () => {
    const text = readFileSync(skillPath, "utf8")
    const blocks = extractInvocationBlocks(text, tool)
    expect(blocks.length).toBeGreaterThan(0)
  })

  test(`pentest-verify/SKILL.md's real ${tool} invocations use only declared/bounded flags (no escalation, no new flags)`, () => {
    const text = readFileSync(skillPath, "utf8")
    const blocks = extractInvocationBlocks(text, tool)
    expect(blocks.length).toBeGreaterThan(0)
    for (const block of blocks) {
      const tokens = block.match(/(?:^|[\s"'])(--?[A-Za-z][A-Za-z-]*)\b/g) ?? []
      for (const raw of tokens) {
        const flag = raw.trim().replace(/^["']/, "")
        expect(BOUNDED_FLAGS[tool]).toContain(flag)
      }
    }
  })
}

test("pentest-verify/SKILL.md documents bh-exec re-checking scope on every re-run call", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/re-check/i)
  expect(text).toMatch(/scope/i)
})

test("pentest-verify/SKILL.md documents a 'what this skill does not do' scope section", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/does not do/i)
})

// --- /verify command ---

test("/verify command file exists with a <command-instruction> block", () => {
  const text = readFileSync(verifyCmdPath, "utf8")
  expect(text).toMatch(/<command-instruction>/)
  expect(text).toMatch(/<\/command-instruction>/)
})

test("/verify command loads and follows the pentest-verify skill", () => {
  const text = readFileSync(verifyCmdPath, "utf8")
  expect(text).toMatch(/pentest-verify/)
})

test("/verify command has a description frontmatter field", () => {
  const text = readFileSync(verifyCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

// Locked project decision (same as test/enum-skill.test.mjs and
// test/exploit-skill.test.mjs): the verify skill/command are authored from
// scratch for boundhound, with zero attribution to (or naming of) any
// external or upstream pentesting project/platform. Each sentinel is
// checked as a whole word (case-insensitive) so it cannot false-positive on
// an unrelated English or technical token that merely shares letters.
const EXTERNAL_PROJECT_SENTINELS = [
  "owasp",
  "mitre",
  "hacktricks",
  "seclists",
  "metasploit",
  "burp suite",
  "portswigger",
  "rapid7",
  "shodan",
  "kali linux",
  "pentestgpt",
  "hexstrike",
  "cybersecurity ai",
  "\\bcai\\b",
]

function assertNoExternalProjectReferences(filePath) {
  const text = readFileSync(filePath, "utf8")
  for (const word of EXTERNAL_PROJECT_SENTINELS) {
    const pattern = word.startsWith("\\b") ? new RegExp(word, "i") : new RegExp(`\\b${word}\\b`, "i")
    expect(text).not.toMatch(pattern)
  }
}

test("pentest-verify/SKILL.md has no external-project references", () => {
  assertNoExternalProjectReferences(skillPath)
})

test("/verify command has no external-project references", () => {
  assertNoExternalProjectReferences(verifyCmdPath)
})

// English hygiene: same sentinel discipline as test/enum-skill.test.mjs and
// test/exploit-skill.test.mjs — each Indonesian word/phrase is checked as a
// whole word (or literal substring for the two-word phrase) so it cannot
// false-positive on an English word or technical token that merely contains
// the same letters (e.g. \bdan\b does not match "candy").
const INDONESIAN_SENTINELS = [
  "dan",
  "pada",
  "jangan",
  "nyalakan",
  "isi",
  "tanyakan",
  "ingatkan",
  "boleh",
  "lewat",
  "mulai",
  "milik",
  "sesuai",
  "daftar",
  "nama",
  "aktif",
  "kontrak",
  "bukti izin",
]

function assertNoIndonesian(filePath) {
  const text = readFileSync(filePath, "utf8")
  for (const word of INDONESIAN_SENTINELS) {
    const pattern = word.includes(" ") ? new RegExp(word, "i") : new RegExp(`\\b${word}\\b`, "i")
    expect(text).not.toMatch(pattern)
  }
}

test("pentest-verify/SKILL.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(skillPath)
})

test("verify.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(verifyCmdPath)
})
