// test/burp-skill.test.mjs
//
// Phase 8 (Task 4): the pentest-burp skill documents boundhound's Burp Suite
// safety model. Burp Suite (Burp Pro, for active scan) runs on the
// operator's HOST, not inside the engagement container, and its MCP tool
// calls send their own HTTP requests directly — they never pass through
// bh-exec, the choke point every other tool in this system goes through
// (src/guard/burp-guard.mjs, hooks/scope-guard.mjs). Instead, a SEPARATE
// choke point — the PreToolUse scope guard — intercepts every Burp MCP tool
// call and scope-checks its target deny-by-default: no active scope, an
// unresolved/ambiguous/suspicious target, or an out-of-scope target are all
// denied and written to the engagement audit log. The operator additionally
// mirrors scope into Burp's own Target Scope via `bh-burp-scope`
// (bin/bh-burp-scope.mjs), as defense in depth. The /burp command loads and
// follows the skill.
//
// This is a STATIC structural check — it reads SKILL.md/burp.md as text and
// asserts on their shape/content, mirroring test/workflow-skill.test.mjs. It
// does not invoke burp-guard.mjs or bh-burp-scope.mjs directly (those have
// their own suites).
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(import.meta.dir, "..")
const skillPath = join(repoRoot, ".claude", "skills", "pentest-burp", "SKILL.md")
const burpCmdPath = join(repoRoot, ".claude", "commands", "burp.md")

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a skill/command markdown file and parses it as YAML.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

// --- frontmatter -----------------------------------------------------

test("pentest-burp/SKILL.md exists and has a name field", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-burp")
})

test("pentest-burp/SKILL.md has a non-empty description", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("pentest-burp/SKILL.md description declares triggers", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.description).toMatch(/Triggers:/)
})

test("pentest-burp/SKILL.md phase includes burp", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("burp")
})

test("pentest-burp/SKILL.md tools field notes Burp MCP is host-side", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.tools).toBeDefined()
  expect(JSON.stringify(fm.tools)).toMatch(/host/i)
})

// --- SAFETY: host/Pro + separate choke point + deny-by-default -----------

test("pentest-burp/SKILL.md states Burp Suite runs on the host, not the container", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\bhost\b/i)
  expect(text).not.toMatch(/runs? (inside|in) the container/i)
})

test("pentest-burp/SKILL.md states Burp Pro is required for active scan", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/Burp Pro/)
  expect(text).toMatch(/active scan/i)
})

test("pentest-burp/SKILL.md states Burp MCP tool calls do NOT go through bh-exec", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-exec/)
  expect(text).toMatch(/(never|do not|does not|don't|doesn't) (pass|go) through bh-exec/i)
})

test("pentest-burp/SKILL.md states Burp MCP calls are scope-checked by a PreToolUse guard", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/PreToolUse/)
  expect(text).toMatch(/scope[- ]check/i)
})

test("pentest-burp/SKILL.md states the guard is deny-by-default", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/deny-by-default/i)
})

test("pentest-burp/SKILL.md states an out-of-scope Burp target is denied and audited", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/out-of-scope/i)
  expect(text).toMatch(/denied/i)
  expect(text).toMatch(/audit/i)
})

test("pentest-burp/SKILL.md states a denied Burp call is skipped, not forced", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/skipped,?\s+not forced/i)
})

// --- bh-burp-scope mirror step (defense in depth) -------------------------

test("pentest-burp/SKILL.md documents mirroring scope via bh-burp-scope", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/bh-burp-scope/)
  expect(text).toMatch(/defense.in.depth/i)
})

test("pentest-burp/SKILL.md documents the Target Scope output file and loading it into Burp", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/output\/burp\/target-scope\.json/)
  expect(text).toMatch(/Target/)
  expect(text).toMatch(/Scope/)
})

// --- precondition ------------------------------------------------------

test("pentest-burp/SKILL.md requires an active, authorized, in-scope engagement and points to /engagement if missing", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/active engagement/i)
  expect(text).toMatch(/authoriz/i)
  expect(text).toMatch(/in.scope/i)
  expect(text).toMatch(/\/engagement\b/)
})

// --- honesty about current state: enforcement is live, live drive-through is not claimed --

test("pentest-burp/SKILL.md does not claim boundhound currently drives Burp scans automatically", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).not.toMatch(/boundhound (scans|drives|runs) (with )?burp automatically/i)
})

test("pentest-burp/SKILL.md states the guard and audit enforcement are live/tested", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/(live|already enforced|enforced today)/i)
  expect(text).toMatch(/tested/i)
})

// --- /burp command ---

test("/burp command file exists with a <command-instruction> block", () => {
  const text = readFileSync(burpCmdPath, "utf8")
  expect(text).toMatch(/<command-instruction>/)
  expect(text).toMatch(/<\/command-instruction>/)
})

test("/burp command loads and follows the pentest-burp skill", () => {
  const text = readFileSync(burpCmdPath, "utf8")
  expect(text).toMatch(/pentest-burp/)
})

test("/burp command has a description frontmatter field", () => {
  const text = readFileSync(burpCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("/burp command frontmatter name is pentest-burp", () => {
  const text = readFileSync(burpCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-burp")
})

test("/burp command frontmatter phase includes burp", () => {
  const text = readFileSync(burpCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("burp")
})

test("/burp command mentions bh-burp-scope", () => {
  const text = readFileSync(burpCmdPath, "utf8")
  expect(text).toMatch(/bh-burp-scope/)
})

// Locked project decision (same as test/workflow-skill.test.mjs and
// siblings): authored from scratch for boundhound, with zero attribution to
// (or naming of) any external or upstream pentesting project/platform.
// UNLIKE those sibling suites, "burp suite" itself is NOT a forbidden
// sentinel here — Burp Suite is the very subject of this skill, so the
// skill and command legitimately name it throughout. Every other
// third-party project/tool-suite name (including Burp's own vendor,
// PortSwigger) remains forbidden. Each sentinel is checked as a whole word
// (case-insensitive) so it cannot false-positive on an unrelated English or
// technical token that merely shares letters.
const EXTERNAL_PROJECT_SENTINELS = [
  "owasp",
  "mitre",
  "hacktricks",
  "seclists",
  "metasploit",
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

test("pentest-burp/SKILL.md has no external-project references (beyond Burp Suite itself)", () => {
  assertNoExternalProjectReferences(skillPath)
})

test("/burp command has no external-project references (beyond Burp Suite itself)", () => {
  assertNoExternalProjectReferences(burpCmdPath)
})

// English hygiene: same sentinel discipline as test/workflow-skill.test.mjs —
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

test("pentest-burp/SKILL.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(skillPath)
})

test("/burp command has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(burpCmdPath)
})
