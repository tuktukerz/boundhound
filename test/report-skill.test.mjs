// test/report-skill.test.mjs
//
// Phase 5 report (Task 3): the pentest-report skill runs bh-report over the
// active engagement's already-verified findings.json + scope.yaml and
// summarizes the resulting report.md for the operator. The /report command
// loads + follows it. This is a STATIC structural check — it reads
// SKILL.md/report.md as text and asserts on their shape/content, mirroring
// test/verify-skill.test.mjs and test/exploit-skill.test.mjs. It does not
// invoke bh-report.mjs or buildReport (those have their own suites:
// bin/bh-report.test.mjs, src/report/report.test.mjs).
//
// NO-FABRICATION (spec §4/§5): this skill is a doc-generator wrapper, not an
// attack tool — `tools: []` — and it must never instruct the operator (or
// itself) to hand-write, embellish, or invent a finding, severity, or piece
// of evidence. The report is derived deterministically from findings.json +
// scope.yaml; this suite's SAFETY section asserts the skill says so in
// plain language and never tells the agent to author findings by hand.
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(import.meta.dir, "..")
const skillPath = join(repoRoot, ".claude", "skills", "pentest-report", "SKILL.md")
const reportCmdPath = join(repoRoot, ".claude", "commands", "report.md")

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a skill/command markdown file and parses it as YAML.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

// --- frontmatter -----------------------------------------------------

test("pentest-report/SKILL.md exists and has a name field", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.name).toBe("pentest-report")
})

test("pentest-report/SKILL.md has a non-empty description", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

test("pentest-report/SKILL.md description declares triggers", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(fm.description).toMatch(/Triggers:/)
})

test("pentest-report/SKILL.md phase includes report", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.phase)).toBe(true)
  expect(fm.phase).toContain("report")
})

test("pentest-report/SKILL.md category includes report", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.category)).toBe(true)
  expect(fm.category).toContain("report")
})

test("pentest-report/SKILL.md tools is an empty array (no external attack tool — it is a doc generator)", () => {
  const text = readFileSync(skillPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(Array.isArray(fm.tools)).toBe(true)
  expect(fm.tools.length).toBe(0)
})

// --- positive routing: bh-report is actually invoked, plugin + dev mode ---

test("pentest-report/SKILL.md invokes bh-report.mjs via the plugin-mode form (CLAUDE_PLUGIN_ROOT / CLAUDE_PLUGIN_DATA)", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/\$\{CLAUDE_PLUGIN_ROOT\}\/bin\/bh-report\.mjs/)
  expect(text).toMatch(/--data-dir\s+"\$\{CLAUDE_PLUGIN_DATA\}"/)
})

test("pentest-report/SKILL.md documents the dev-mode fallback invocation (repo-relative, no --data-dir)", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/dev mode/i)
  expect(text).toMatch(/node bin\/bh-report\.mjs/)
})

test("pentest-report/SKILL.md documents where bh-report writes its output", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/output\/report\/report\.md/)
})

// --- precondition ------------------------------------------------------

test("pentest-report/SKILL.md requires an active engagement and findings.json, and says to run /verify first if missing", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/active engagement/i)
  expect(text).toMatch(/findings\.json/)
  expect(text).toMatch(/\/verify\b/)
})

test("pentest-report/SKILL.md notes a broken scope makes bh-report fail-closed", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/fail-closed|fail closed/i)
  expect(text).toMatch(/\bcode 3\b|\bexit code 3\b/i)
  expect(text).toMatch(/\bscope\b/i)
})

// --- summarize the generated report, without altering it ---------------

test("pentest-report/SKILL.md instructs reading and summarizing the generated report.md for the operator", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/summariz/i)
  expect(text).toMatch(/report\.md/)
})

test("pentest-report/SKILL.md instructs summarizing counts by severity and top findings", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/severity/i)
})

// --- SAFETY: no-fabrication — the load-bearing assertions for this skill ---

test("pentest-report/SKILL.md states the report renders only verified engagement data", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/renders? only/i)
})

test("pentest-report/SKILL.md states the report never invents findings, severities, or evidence", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/never invent/i)
})

// The safety framing itself legitimately uses words like "embellish" /
// "fabricate" / "write findings" in NEGATED form ("never embellishes",
// "does not write findings", "rather than a fabricated ... one") — banning
// the bare words would fail the very sentences that state the no-fabrication
// guarantee. Instead, check that every occurrence of a risky phrase is
// actually negated (preceded within a short window by a negation cue like
// "not"/"never"/"n't"/"rather than"/"no "), i.e. there is no UNGUARDED
// instruction to hand-write, add, embellish, or fabricate a finding.
const NEGATION_CUE = /\b(not|never|n't|rather than|no|against|safe)\b/i

function assertNoUnguardedFabricationInstruction(text, pattern, windowBefore = 40) {
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g")
  let m
  while ((m = re.exec(text))) {
    const start = Math.max(0, m.index - windowBefore)
    const context = text.slice(start, m.index)
    expect(context).toMatch(NEGATION_CUE)
  }
}

test("pentest-report/SKILL.md does not instruct the agent to hand-write, embellish, or fabricate findings", () => {
  const text = readFileSync(skillPath, "utf8")
  // Every mention of these risky phrasings must be a negated safety
  // statement, never a bare instruction to do the thing.
  assertNoUnguardedFabricationInstruction(text, /write (a |the )?finding/i)
  assertNoUnguardedFabricationInstruction(text, /add (a |your own )?finding/i)
  assertNoUnguardedFabricationInstruction(text, /embellish/i)
  assertNoUnguardedFabricationInstruction(text, /fabricat/i)
  assertNoUnguardedFabricationInstruction(text, /make up (a |the )?finding/i)
})

test("pentest-report/SKILL.md states the report is derived deterministically from findings.json + scope.yaml", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/deterministic/i)
  expect(text).toMatch(/findings\.json/)
  expect(text).toMatch(/scope\.yaml/)
})

test("pentest-report/SKILL.md instructs not altering the generated report file", () => {
  const text = readFileSync(skillPath, "utf8")
  expect(text).toMatch(/without altering|do not (edit|alter|modify)|never (edit|alter|modify)/i)
})

// --- /report command ---

test("/report command file exists with a <command-instruction> block", () => {
  const text = readFileSync(reportCmdPath, "utf8")
  expect(text).toMatch(/<command-instruction>/)
  expect(text).toMatch(/<\/command-instruction>/)
})

test("/report command loads and follows the pentest-report skill", () => {
  const text = readFileSync(reportCmdPath, "utf8")
  expect(text).toMatch(/pentest-report/)
})

test("/report command has a description frontmatter field", () => {
  const text = readFileSync(reportCmdPath, "utf8")
  const fm = parseFrontmatter(text)
  expect(typeof fm.description).toBe("string")
  expect(fm.description.trim().length).toBeGreaterThan(0)
})

// Locked project decision (same as test/verify-skill.test.mjs,
// test/enum-skill.test.mjs, test/exploit-skill.test.mjs): the report
// skill/command are authored from scratch for boundhound, with zero
// attribution to (or naming of) any external or upstream pentesting
// project/platform. Each sentinel is checked as a whole word
// (case-insensitive) so it cannot false-positive on an unrelated English or
// technical token that merely shares letters.
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

test("pentest-report/SKILL.md has no external-project references", () => {
  assertNoExternalProjectReferences(skillPath)
})

test("/report command has no external-project references", () => {
  assertNoExternalProjectReferences(reportCmdPath)
})

// English hygiene: same sentinel discipline as test/verify-skill.test.mjs —
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

test("pentest-report/SKILL.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(skillPath)
})

test("report.md has no residual Indonesian sentinel words", () => {
  assertNoIndonesian(reportCmdPath)
})
