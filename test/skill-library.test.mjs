// test/skill-library.test.mjs
//
// Phase 9 (Task 1): `skills-library/` is a broad, self-authored
// technique-playbook library (source breadth) — NOT the active per-phase
// skill set in `.claude/skills/`. Nothing here is auto-promoted; promoting a
// library playbook into an active skill is a separate, deliberate act. To
// let later batches add ~100 skills safely, this suite globs EVERY
// `skills-library/<slug>/SKILL.md` and enforces the same invariants on each
// one (spec §2): frontmatter shape, name==folder, a `Triggers:` line,
// English-only, no external-project references, explicit Boundhound wiring,
// and a non-trivial body. Every per-skill assertion names the skill in its
// test title so a bad file in a later batch fails loudly and is easy to
// find. Today the library holds only `pentest-mode`; the aggregate
// growth-floor test is written to rise (never fall) as batches T2-T11 land.
//
// Frontmatter parsing and both sentinel-word arrays are carried over from
// test/workflow-skill.test.mjs byte-identical, so the whole repo forbids
// the same words consistently.
import { test, expect, describe } from "bun:test"
import { readFileSync, readdirSync, statSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { parse as parseYaml } from "yaml"

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..")
const skillsLibraryDir = join(repoRoot, "skills-library")
const indexPath = join(skillsLibraryDir, "README.md")

// --- discovery: every skills-library/<slug>/SKILL.md, sorted for
// deterministic test ordering/output --------------------------------------

function discoverSkills() {
  const entries = readdirSync(skillsLibraryDir, { withFileTypes: true })
  const slugs = entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort()
  const found = []
  for (const slug of slugs) {
    const skillPath = join(skillsLibraryDir, slug, "SKILL.md")
    let isFile = false
    try {
      isFile = statSync(skillPath).isFile()
    } catch {
      isFile = false // no SKILL.md under this folder -> not a skill dir
    }
    if (isFile) found.push({ slug, path: skillPath })
  }
  return found
}

const skills = discoverSkills()

// Pulls the YAML frontmatter block (between the first two `---` lines) out
// of a SKILL.md file and parses it as YAML. Byte-identical approach to
// test/workflow-skill.test.mjs's parseFrontmatter.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

// Everything after the closing `---` of the frontmatter block.
function bodyOf(text) {
  return text.replace(/^---\n[\s\S]*?\n---\n/, "")
}

// --- sentinel word lists, reused byte-identical from
// test/workflow-skill.test.mjs so the whole repo forbids the same words
// consistently. Burp/Burp Suite is deliberately NOT in this list (spec §2 /
// plan Global Constraints: Burp is allowed as a subject). ------------------

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

// --- Boundhound wiring (spec §2) ------------------------------------------
//
// The body must mention at least one of: bh-exec, a bounded tool, a phase
// command, or the scope model — so no skill is generic prose detached from
// our system.
//
// Calibration note (per Task 1 brief): `pentest-mode` is the one skill that
// pre-dates this harness, and it does NOT mention bh-exec, any bounded
// tool, or a phase command. It DOES have a "Mode Presets" table with a
// `Scope` column ("| Mode | Scope | Stealth | Parallelism | Speed |"), which
// satisfies the `scope` arm exactly as specified — so the wiring check below
// is the base check from spec §2 (bh-exec / bounded tool / phase command /
// scope), unwidened, and pentest-mode passes it as-is. No broadening to
// engagement/skill-chain was needed.
const BOUNDED_TOOLS = ["subfinder", "httpx", "nmap", "ffuf", "nuclei", "sqlmap"]
const PHASE_COMMANDS = ["/recon", "/enum", "/exploit", "/verify", "/report", "/fullscan", "/burp"]

function hasBoundhoundWiring(body) {
  if (/bh-exec/i.test(body)) return true
  if (BOUNDED_TOOLS.some((tool) => new RegExp(`\\b${tool}\\b`, "i").test(body))) return true
  if (PHASE_COMMANDS.some((cmd) => body.includes(cmd))) return true
  if (/\bscope\b/i.test(body)) return true
  return false
}

// --- per-skill invariants --------------------------------------------------
//
// If the library is ever empty, fail loudly instead of the loop below
// silently registering zero tests (which `bun test` would report as green).
if (skills.length === 0) {
  test("skills-library/ has at least one <slug>/SKILL.md to validate", () => {
    expect(skills.length).toBeGreaterThan(0)
  })
}

for (const { slug, path } of skills) {
  describe(`skills-library/${slug}/SKILL.md`, () => {
    const text = readFileSync(path, "utf8")

    test(`${slug}: frontmatter parses and has name, description, category, tags`, () => {
      let fm
      expect(() => {
        fm = parseFrontmatter(text)
      }).not.toThrow()
      expect(typeof fm.name).toBe("string")
      expect(typeof fm.description).toBe("string")
      expect(fm.category).toBeTruthy()
      expect(fm.tags).toBeTruthy()
    })

    test(`${slug}: name equals the folder slug`, () => {
      const fm = parseFrontmatter(text)
      expect(fm.name).toBe(slug)
    })

    test(`${slug}: folder slug is lowercase-kebab`, () => {
      expect(slug).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/)
    })

    test(`${slug}: description contains a Triggers: line and is non-empty`, () => {
      const fm = parseFrontmatter(text)
      expect(fm.description.trim().length).toBeGreaterThan(0)
      expect(fm.description).toMatch(/Triggers:/)
    })

    test(`${slug}: is English-only (no residual Indonesian sentinel words)`, () => {
      assertNoIndonesian(path)
    })

    test(`${slug}: has no external project/vendor references`, () => {
      assertNoExternalProjectReferences(path)
    })

    test(`${slug}: is wired to Boundhound (bh-exec / bounded tool / phase command / scope)`, () => {
      expect(hasBoundhoundWiring(bodyOf(text))).toBe(true)
    })

    test(`${slug}: body is non-trivial (minimum length + at least one ## heading)`, () => {
      const body = bodyOf(text)
      expect(body.trim().length).toBeGreaterThan(300)
      expect(body).toMatch(/^##\s+\S.*$/m)
    })
  })
}

// --- aggregate: growth floor -----------------------------------------------
//
// Only `pentest-mode` exists today. Tasks 2-11 add ~90-110 more skills
// across the spec §3 categories; each landed batch should raise this floor,
// never lower it. Keep it a floor ("at least"), not an exact count, so it
// stays green through every batch.
test("skills-library has at least 1 skill (growth floor -- raise as batches land, never lower)", () => {
  expect(skills.length).toBeGreaterThanOrEqual(1)
})

// --- aggregate: every category used by a skill is listed in the index -----

test("every category used by a skill appears in skills-library/README.md", () => {
  const indexText = readFileSync(indexPath, "utf8")
  const usedCategories = new Set()
  for (const { path } of skills) {
    const text = readFileSync(path, "utf8")
    const fm = parseFrontmatter(text)
    const categories = Array.isArray(fm.category) ? fm.category : [fm.category]
    for (const category of categories) usedCategories.add(String(category))
  }
  for (const category of usedCategories) {
    expect(indexText).toContain(category)
  }
})
