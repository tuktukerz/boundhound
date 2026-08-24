// test/enum-skill.test.mjs
//
// Phase 2 enum (Task 5): the pentest-enum skill orchestrates
// ffuf -> nuclei -> bh-enum-map, all via bh-exec, consuming the prior
// phase's recon-map.json. The /enum command loads + follows it. This is a
// STATIC structural check — it reads SKILL.md/enum.md as text and asserts
// on their shape/content, mirroring test/recon-skill.test.mjs. It does not
// invoke bh-exec or any real tool (those have their own suites).
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(import.meta.dir, "..")
const skillPath = join(repoRoot, ".claude", "skills", "pentest-enum", "SKILL.md")
const enumCmdPath = join(repoRoot, ".claude", "commands", "enum.md")

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a skill/command markdown file and parses it as YAML.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

test("pentest-enum/SKILL.md exists and has a name field", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-enum")
})

test("pentest-enum/SKILL.md has a non-empty description", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("pentest-enum/SKILL.md description declares triggers", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.description).toMatch(/Triggers:/)
})

test("pentest-enum/SKILL.md phase includes enum", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("enum")
})

test("pentest-enum/SKILL.md category includes enum", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.category)).toBe(true)
  expect(fm.category).toContain("enum")
})

test("pentest-enum/SKILL.md tools list ffuf and nuclei", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.tools)).toBe(true)
  expect(fm.tools).toContain("ffuf")
  expect(fm.tools).toContain("nuclei")
})

test("pentest-enum/SKILL.md orchestrates every tool exclusively via bh-exec", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-exec/)
  // Positive check: each enum tool must actually be invoked through a real
  // `bh-exec.mjs <tool> --target` call — both the plugin-mode form (quoted
  // path, e.g. `.../bh-exec.mjs" ffuf --target`) and the dev-mode form
  // (`bin/bh-exec.mjs ffuf --target`) match this. A bare negative check
  // (e.g. "no `ffuf -u` outside bh-exec") is near-vacuous — it would pass
  // even if the skill never routed a tool through bh-exec at all — so
  // assert the actual routing exists for every tool instead.
  for (const tool of ["ffuf", "nuclei"]) {
    expect(text).toMatch(new RegExp(`bh-exec\\.mjs"?\\s+${tool}\\s+--target`))
  }
})

test("pentest-enum/SKILL.md requires recon-map.json and tells the operator to run /recon first if missing", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/recon-map\.json/)
  expect(text).toMatch(/\/recon/)
})

test("pentest-enum/SKILL.md documents the *.<domain> scope note as inherited from recon", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\*\.<domain>/)
  expect(text).toMatch(/inherit/i)
})

test("pentest-enum/SKILL.md documents ffuf's FUZZ-URL usage and the bundled wordlist path", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\/FUZZ/)
  expect(text).toMatch(/\/usr\/share\/boundhound\/wordlists\/common\.txt/)
})

test("pentest-enum/SKILL.md documents nuclei's online-templates vs bundled/offline distinction", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/online/i)
  expect(text).toMatch(/bundled/i)
  expect(text).toMatch(/offline/i)
})

test("pentest-enum/SKILL.md documents the ffuf and nuclei safety caps", () => {
  const text = readFileSync(skillPath, "utf8")
  // ffuf threads/rate and nuclei concurrency/rate-limit are all safety-capped
  // (spec §6) — the skill must say so, not just use the flags silently.
  expect(text).toMatch(/safety[- ]capp?ed/i)
  expect(text).toMatch(/-c\b/)
  expect(text).toMatch(/-rl\b/)
})

test("pentest-enum/SKILL.md documents the output/enum/ layout", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/output\/enum/)
  expect(text).toMatch(/enum-map\.json/)
})

test("pentest-enum/SKILL.md documents the bh-enum-map step", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-enum-map/)
})

test("/enum command file exists with a <command-instruction> block", () => {
  const text = readFileSync(enumCmdPath, "utf8")
  expect(text).toMatch(/<command-instruction>/)
  expect(text).toMatch(/<\/command-instruction>/)
})

test("/enum command loads and follows the pentest-enum skill", () => {
  const text = readFileSync(enumCmdPath, "utf8")
  expect(text).toMatch(/pentest-enum/)
})

test("/enum command has a description frontmatter field", () => {
  const text = readFileSync(enumCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

// Locked project decision: the enum skill/command are authored from scratch
// for boundhound, with zero attribution to (or naming of) any external or
// upstream pentesting project/platform. Each sentinel is checked as a whole
// word (case-insensitive) so it cannot false-positive on an unrelated English
// or technical token that merely shares letters (e.g. \bcai\b does not match
// "certain"; ffuf/nuclei/projectdiscovery — boundhound's own declared
// tools-catalog entries — never match any of these).
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

test("pentest-enum/SKILL.md has no external-project references", () => {
  assertNoExternalProjectReferences(skillPath)
})

test("/enum command has no external-project references", () => {
  assertNoExternalProjectReferences(enumCmdPath)
})

// English hygiene: same sentinel discipline as test/recon-skill.test.mjs —
// each Indonesian word/phrase is checked as a whole word (or literal
// substring for the two-word phrase) so it cannot false-positive on an
// English word or technical token that merely contains the same letters
// (e.g. \bdan\b does not match "candy").
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

test("pentest-enum/SKILL.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(skillPath)
})

test("enum.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(enumCmdPath)
})
