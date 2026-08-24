// test/recon-skill.test.mjs
//
// Phase 1 recon (Task 7): the pentest-recon skill orchestrates
// subfinder -> httpx -> nmap -> bh-recon-map, all via bh-exec, and the
// /recon command loads + follows it. This is a STATIC structural check —
// it reads SKILL.md/recon.md/mode.md/engagement.md/scope.yaml as text and
// asserts on their shape/content. It does not invoke bh-exec or any real
// tool (those have their own suites).
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(import.meta.dir, "..")
const skillPath = join(repoRoot, ".claude", "skills", "pentest-recon", "SKILL.md")
const reconCmdPath = join(repoRoot, ".claude", "commands", "recon.md")
const modeCmdPath = join(repoRoot, ".claude", "commands", "mode.md")
const engagementCmdPath = join(repoRoot, ".claude", "commands", "engagement.md")
const scopeTemplatePath = join(repoRoot, "engagements", "templates", "scope.yaml")

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a skill/command markdown file and parses it as YAML.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

test("pentest-recon/SKILL.md exists and has a name field", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-recon")
})

test("pentest-recon/SKILL.md has a non-empty description", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("pentest-recon/SKILL.md description declares triggers", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.description).toMatch(/Triggers:/)
})

test("pentest-recon/SKILL.md phase includes recon", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("recon")
})

test("pentest-recon/SKILL.md category includes recon", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.category)).toBe(true)
  expect(fm.category).toContain("recon")
})

test("pentest-recon/SKILL.md tools list subfinder, httpx, and nmap", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.tools)).toBe(true)
  expect(fm.tools).toContain("subfinder")
  expect(fm.tools).toContain("httpx")
  expect(fm.tools).toContain("nmap")
})

test("pentest-recon/SKILL.md orchestrates every tool exclusively via bh-exec", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-exec/)
  // Positive check: each recon tool must actually be invoked through a real
  // `bh-exec.mjs <tool> --target` call — both the plugin-mode form (quoted
  // path, e.g. `.../bh-exec.mjs" subfinder --target`) and the dev-mode form
  // (`bin/bh-exec.mjs subfinder --target`) match this. A bare negative check
  // (e.g. "no `subfinder -d` outside bh-exec") is near-vacuous — it would
  // pass even if the skill never routed a tool through bh-exec at all — so
  // assert the actual routing exists for every tool instead.
  for (const tool of ["subfinder", "httpx", "nmap"]) {
    expect(text).toMatch(new RegExp(`bh-exec\\.mjs"?\\s+${tool}\\s+--target`))
  }
})

test("pentest-recon/SKILL.md documents the *.<domain> in_scope requirement for subdomains", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\*\.<domain>/)
})

test("pentest-recon/SKILL.md documents the output/recon/ layout", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/output\/recon/)
  expect(text).toMatch(/recon-map\.json/)
})

test("/recon command file exists with a <command-instruction> block", () => {
  const text = readFileSync(reconCmdPath, "utf8")
  expect(text).toMatch(/<command-instruction>/)
  expect(text).toMatch(/<\/command-instruction>/)
})

test("/recon command loads and follows the pentest-recon skill", () => {
  const text = readFileSync(reconCmdPath, "utf8")
  expect(text).toMatch(/pentest-recon/)
})

test("/recon command has a description frontmatter field", () => {
  const text = readFileSync(reconCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

// English hygiene: mode.md, engagement.md, recon.md, and the scope template
// must contain none of these Indonesian sentinel words. Each is checked as
// a whole word (or, for the two-word phrase, a literal substring) so it
// cannot false-positive on an English word or technical token that merely
// contains the same letters (e.g. \bdan\b does not match "candy").
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

test("mode.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(modeCmdPath)
})

test("engagement.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(engagementCmdPath)
})

test("recon.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(reconCmdPath)
})

test("scope.yaml template has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(scopeTemplatePath)
})

test("scope.yaml template's authorization comment is in English", () => {
  const text = readFileSync(scopeTemplatePath, "utf8")
  expect(text).toMatch(/proof of authorization/i)
})
