// test/workflow-skill.test.mjs
//
// Phase 6 orchestrator (Task 3): the pentest-workflow skill runs the ENTIRE
// engagement chain (recon -> enum -> exploit -> findings -> report) in one
// pass via bh-fullscan. The /fullscan command loads + follows it. This is a
// STATIC structural check — it reads SKILL.md/fullscan.md as text and
// asserts on their shape/content, mirroring test/report-skill.test.mjs and
// test/exploit-skill.test.mjs. It does not invoke bh-fullscan.mjs or
// runFullscan (those have their own suites: bin/bh-fullscan.test.mjs,
// src/orchestrate/fullscan.test.mjs).
//
// SAFETY (spec §4/§5, this phase's whole story): the orchestrator adds no
// new capability and no new attack surface — every tool step it plans still
// goes through the same bh-exec choke point (scope + safety + audit +
// container) every other phase already uses. This suite's SAFETY section
// asserts the skill says so in plain language, states the orchestrator can
// never exceed any per-phase bound, and states a step bh-exec denies is
// skipped, never forced.
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(import.meta.dir, "..")
const skillPath = join(repoRoot, ".claude", "skills", "pentest-workflow", "SKILL.md")
const fullscanCmdPath = join(repoRoot, ".claude", "commands", "fullscan.md")

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a skill/command markdown file and parses it as YAML.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

// --- frontmatter -----------------------------------------------------

test("pentest-workflow/SKILL.md exists and has a name field", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-workflow")
})

test("pentest-workflow/SKILL.md has a non-empty description", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("pentest-workflow/SKILL.md description declares triggers", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.description).toMatch(/Triggers:/)
})

test("pentest-workflow/SKILL.md phase includes orchestrator", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("orchestrator")
})

test("pentest-workflow/SKILL.md category includes orchestrator", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.category)).toBe(true)
  expect(fm.category).toContain("orchestrator")
})

test("pentest-workflow/SKILL.md tools lists every orchestrated tool", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.tools)).toBe(true)
  for (const tool of ["subfinder", "httpx", "nmap", "nuclei", "ffuf", "sqlmap"]) {
    expect(fm.tools).toContain(tool)
  }
})

// --- positive routing: bh-fullscan is actually invoked, plugin + dev mode --

test("pentest-workflow/SKILL.md invokes bh-fullscan.mjs via the plugin-mode form (CLAUDE_PLUGIN_ROOT / CLAUDE_PLUGIN_DATA)", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\$\{CLAUDE_PLUGIN_ROOT\}\/bin\/bh-fullscan\.mjs/)
  expect(text).toMatch(/--data-dir\s+"\$\{CLAUDE_PLUGIN_DATA\}"/)
})

test("pentest-workflow/SKILL.md documents the dev-mode fallback invocation (repo-relative, no --data-dir)", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/dev mode/i)
  expect(text).toMatch(/node bin\/bh-fullscan\.mjs/)
})

test("pentest-workflow/SKILL.md mentions --no-exploit for a non-intrusive recon+enum+report run", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/--no-exploit/)
})

test("pentest-workflow/SKILL.md documents where the final report is written", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/output\/report\/report\.md/)
})

// --- precondition ------------------------------------------------------

test("pentest-workflow/SKILL.md requires an active, authorized, in-scope engagement and points to /engagement if missing", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/active engagement/i)
  expect(text).toMatch(/authoriz/i)
  expect(text).toMatch(/in.scope/i)
  expect(text).toMatch(/\/engagement\b/)
})

// --- step-by-step alternative: reference the individual phase commands ----

test("pentest-workflow/SKILL.md references the individual phase commands for step-by-step control", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\/recon\b/)
  expect(text).toMatch(/\/enum\b/)
  expect(text).toMatch(/\/exploit\b/)
  expect(text).toMatch(/\/verify\b/)
  expect(text).toMatch(/\/report\b/)
})

// --- SAFETY: the bh-exec choke point story — load-bearing for this skill --

test("pentest-workflow/SKILL.md states every tool step still goes through the bh-exec choke point", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-exec/)
  expect(text).toMatch(/choke point/i)
})

test("pentest-workflow/SKILL.md names all four enforcement layers behind bh-exec", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/scope\s*\+\s*safety\s*\+\s*audit\s*\+\s*container/i)
})

test("pentest-workflow/SKILL.md states the orchestrator never runs a tool directly", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/never runs?\s+a\s+tool\s+directly/i)
})

test("pentest-workflow/SKILL.md states the orchestrator cannot exceed any per-phase bound", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/cannot exceed/i)
  expect(text).toMatch(/bound/i)
})

test("pentest-workflow/SKILL.md states a step bh-exec denies is skipped, not forced", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/skipped,?\s+not forced/i)
})

// --- /fullscan command ---

test("/fullscan command file exists with a <command-instruction> block", () => {
  const text = readFileSync(fullscanCmdPath, "utf8")
  expect(text).toMatch(/<command-instruction>/)
  expect(text).toMatch(/<\/command-instruction>/)
})

test("/fullscan command loads and follows the pentest-workflow skill", () => {
  const text = readFileSync(fullscanCmdPath, "utf8")
  expect(text).toMatch(/pentest-workflow/)
})

test("/fullscan command has a description frontmatter field", () => {
  const text = readFileSync(fullscanCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("/fullscan command mentions --no-exploit", () => {
  const text = readFileSync(fullscanCmdPath, "utf8")
  expect(text).toMatch(/--no-exploit/)
})

// Locked project decision (same as test/report-skill.test.mjs,
// test/verify-skill.test.mjs, test/enum-skill.test.mjs,
// test/exploit-skill.test.mjs): the workflow skill/command are authored from
// scratch for boundhound, with zero attribution to (or naming of) any
// external or upstream pentesting project/platform. Each sentinel is checked
// as a whole word (case-insensitive) so it cannot false-positive on an
// unrelated English or technical token that merely shares letters.
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

test("pentest-workflow/SKILL.md has no external-project references", () => {
  assertNoExternalProjectReferences(skillPath)
})

test("/fullscan command has no external-project references", () => {
  assertNoExternalProjectReferences(fullscanCmdPath)
})

// English hygiene: same sentinel discipline as test/report-skill.test.mjs —
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

test("pentest-workflow/SKILL.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(skillPath)
})

test("/fullscan command has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(fullscanCmdPath)
})
