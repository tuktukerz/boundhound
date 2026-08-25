// test/skill-library-wiring.test.mjs
//
// Wiring-reality gate for the skill library. The structural harness
// (skill-library.test.mjs) proves each skill is well-formed and *mentions*
// Boundhound wiring; this test proves the wiring is REAL — every Boundhound
// tool, phase command, and bh-* CLI a skill names actually exists in the repo,
// and no skill names a foreign attack tool as if it were usable (capability
// fiction). A skill that instructs an action the system can't perform fails
// here.
import { test, expect } from "bun:test"
import { readFileSync, readdirSync, existsSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..")

// --- ground truth, read from the real repo ---
const catalog = JSON.parse(readFileSync(join(repoRoot, "tools-catalog.json"), "utf8"))
const realTools = new Set((catalog.tools ?? []).map((t) => t.tools_name))
const realCommands = new Set(
  readdirSync(join(repoRoot, ".claude/commands"))
    .filter((f) => f.endsWith(".md"))
    .map((f) => f.replace(/\.md$/, "")),
)
const realBins = new Set(
  readdirSync(join(repoRoot, "bin"))
    .filter((f) => f.endsWith(".mjs") && !f.endsWith(".test.mjs"))
    .map((f) => f.replace(/\.mjs$/, "")),
)
if (existsSync(join(repoRoot, "bin/bh-container"))) realBins.add("bh-container")

// Our own tool vocabulary + the phase commands + foreign tools we must NEVER
// present as a usable Boundhound capability.
const KNOWN_TOOLS = ["curl", "subfinder", "httpx", "nmap", "ffuf", "nuclei", "sqlmap"]
const PHASE_COMMANDS = ["recon", "enum", "exploit", "verify", "report", "fullscan", "burp", "engagement", "mode"]
const FOREIGN_TOOLS = [
  "nikto", "metasploit", "wpscan", "gobuster", "hydra", "medusa", "masscan",
  "amass", "dirb", "dirbuster", "wfuzz", "arjun", "dalfox", "commix", "xsstrike",
]

const skillsDir = join(repoRoot, "skills-library")
const slugs = readdirSync(skillsDir).filter((d) => existsSync(join(skillsDir, d, "SKILL.md")))

test("there is a real skill library to audit", () => {
  expect(slugs.length).toBeGreaterThanOrEqual(50)
})

for (const slug of slugs) {
  const body = readFileSync(join(skillsDir, slug, "SKILL.md"), "utf8")

  test(`${slug}: every phase command it names exists`, () => {
    const named = [...new Set([...body.matchAll(/\/([a-z][a-z-]+)\b/g)].map((m) => m[1]))].filter((c) =>
      PHASE_COMMANDS.includes(c),
    )
    for (const c of named) {
      expect(realCommands.has(c), `${slug} names /${c} but .claude/commands/${c}.md does not exist`).toBe(true)
    }
  })

  test(`${slug}: every bounded tool it names exists in the catalog`, () => {
    const named = KNOWN_TOOLS.filter((t) => new RegExp(`\\b${t}\\b`).test(body))
    for (const t of named) {
      expect(realTools.has(t), `${slug} names tool '${t}' but it is not in tools-catalog.json`).toBe(true)
    }
  })

  test(`${slug}: every bh-* CLI it names exists`, () => {
    const named = [...new Set([...body.matchAll(/\b(bh-[a-z-]+)\b/g)].map((m) => m[1]))]
    for (const b of named) {
      expect(realBins.has(b), `${slug} names ${b} but bin/${b}.mjs does not exist`).toBe(true)
    }
  })

  test(`${slug}: names no foreign attack tool as a usable capability`, () => {
    const hits = FOREIGN_TOOLS.filter((t) => new RegExp(`\\b${t}\\b`, "i").test(body))
    expect(hits, `${slug} names foreign tool(s): ${hits.join(", ")}`).toEqual([])
  })
}
