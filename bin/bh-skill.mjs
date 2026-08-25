// bin/bh-skill.mjs
//
// Skill promoter: activates a library technique playbook on demand by
// copying it from skills-library/ (source, not loaded by the plugin) into
// .claude/skills/ (active, loaded by the plugin). This lets an operator turn
// on any of the skills-library playbooks without bloating the always-loaded
// set. Not a network tool -- it only copies/removes directories already on
// disk, so it runs as plain `node bin/bh-skill.mjs` (no docker exec
// involved).
import { join } from "node:path"
import { cpSync, rmSync, existsSync, readdirSync, readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { parse as parseYaml } from "yaml"
import { codeRoot } from "../src/paths.mjs"

// The 8 pipeline skills that must always stay active -- demoting any of
// these would break the phase pipeline the plugin ships with. Kept as a
// literal list (not derived from .claude/skills/'s current contents) so a
// stray extra folder under .claude/skills/ can never accidentally widen or
// narrow what "core" means.
export const CORE_SKILLS = [
  "pentest-recon",
  "pentest-enum",
  "pentest-exploit",
  "pentest-verify",
  "pentest-report",
  "pentest-workflow",
  "pentest-burp",
  "pentest-mode",
]

// Pulls the YAML frontmatter block out of a SKILL.md file -- byte-identical
// approach to test/skill-library.test.mjs's parseFrontmatter, so a
// missing/malformed frontmatter block is treated the same way here as it is
// by that suite.
function parseFrontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!m) throw new Error("no frontmatter block found")
  return parseYaml(m[1])
}

// The description field embeds a "Triggers: '...'" clause (every
// skills-library/*/SKILL.md, enforced by test/skill-library.test.mjs) --
// lift it out verbatim so the promote confirmation can tell the operator
// what phrases just turned this skill on.
function extractTriggers(description) {
  if (typeof description !== "string") return ""
  const i = description.indexOf("Triggers:")
  return i < 0 ? "" : description.slice(i)
}

// { category, triggers } read from <dir>/SKILL.md's frontmatter. Throws if
// the file is missing or its frontmatter doesn't parse -- callers decide how
// to degrade.
function readSkillMeta(dir) {
  const text = readFileSync(join(dir, "SKILL.md"), "utf8")
  const fm = parseFrontmatter(text)
  const category = Array.isArray(fm.category) ? fm.category.join(", ") : (fm.category ?? "unknown")
  return { category, triggers: extractTriggers(fm.description) }
}

// Every skills-library/<slug>/ that actually has a SKILL.md, sorted for
// deterministic output -- same discovery shape as
// test/skill-library.test.mjs's discoverSkills.
function listLibrarySlugs(libDir) {
  if (!existsSync(libDir)) return []
  return readdirSync(libDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((slug) => existsSync(join(libDir, slug, "SKILL.md")))
    .sort()
}

function usage() {
  return [
    "usage: bh-skill <list|promote|demote> [slug] [--force]",
    "  list             list every skills-library/ skill, marking which are active (default)",
    "  promote <slug>   activate a library skill: copy skills-library/<slug>/ into .claude/skills/<slug>/",
    "                   --force re-copies even if already active (overwrites drift)",
    "  demote <slug>    deactivate a promoted library skill: remove .claude/skills/<slug>/",
    "                   refused for the 8 core pipeline skills, and for any active",
    "                   skill with no matching skills-library/<slug>/ entry",
  ].join("\n")
}

function listSkills({ libDir, activeDir }) {
  const slugs = listLibrarySlugs(libDir)
  const skills = slugs.map((slug) => {
    let category = "unknown"
    try {
      category = readSkillMeta(join(libDir, slug)).category
    } catch {
      category = "unknown"
    }
    return { slug, category, active: existsSync(join(activeDir, slug)) }
  })
  const lines = skills.map(
    (s) => `  [${s.active ? "active" : "      "}] ${s.slug.padEnd(32)} ${s.category}`
  )
  const message = [`skills-library (${skills.length} skill(s)):`, ...lines].join("\n")
  return { code: 0, message, skills }
}

// A skill slug must be a plain kebab directory name — never a path. This
// closes any traversal concern for the copy/remove operations below (a slug
// like "../foo" could otherwise resolve outside the skills dirs).
function isValidSlug(slug) {
  return typeof slug === "string" && /^[a-z0-9][a-z0-9-]*$/.test(slug)
}

function promoteSkill({ libDir, activeDir, slug, force }) {
  if (!slug) return { code: 1, message: `bh-skill: promote requires a slug\n\n${usage()}` }
  if (!isValidSlug(slug))
    return { code: 1, message: `bh-skill: promote: "${slug}" is not a valid skill name (a-z, 0-9, hyphen)` }

  const srcDir = join(libDir, slug)
  if (!existsSync(join(srcDir, "SKILL.md"))) {
    return {
      code: 1,
      message: `bh-skill: promote: "${slug}" is not a library skill (no skills-library/${slug}/SKILL.md)`,
    }
  }

  const destDir = join(activeDir, slug)
  const alreadyActive = existsSync(destDir)
  if (alreadyActive && !force) {
    return {
      code: 0,
      message: `${slug} is already active -- nothing to do (pass --force to re-copy from skills-library/)`,
      slug,
    }
  }

  cpSync(srcDir, destDir, { recursive: true })

  let triggers = ""
  try {
    triggers = readSkillMeta(srcDir).triggers
  } catch {
    triggers = ""
  }
  const verb = alreadyActive ? "re-activated" : "activated"
  const message = triggers ? `${verb} ${slug} -- ${triggers}` : `${verb} ${slug}`
  return { code: 0, message, slug }
}

function demoteSkill({ libDir, activeDir, slug }) {
  if (!slug) return { code: 1, message: `bh-skill: demote requires a slug\n\n${usage()}` }
  if (!isValidSlug(slug))
    return { code: 1, message: `bh-skill: demote: "${slug}" is not a valid skill name (a-z, 0-9, hyphen)` }

  if (CORE_SKILLS.includes(slug)) {
    return {
      code: 1,
      message: `bh-skill: demote: "${slug}" is a core pipeline skill and cannot be demoted`,
    }
  }

  const destDir = join(activeDir, slug)
  if (!existsSync(destDir)) {
    return { code: 0, message: `${slug} is not active -- nothing to do`, slug }
  }

  // Safety net: only ever remove a skill this tool could also restore.
  if (!existsSync(join(libDir, slug, "SKILL.md"))) {
    return {
      code: 1,
      message: `bh-skill: demote: "${slug}" is active but has no matching skills-library/${slug}/ entry -- refusing to remove (it could not be restored)`,
    }
  }

  rmSync(destDir, { recursive: true, force: true })
  return { code: 0, message: `deactivated ${slug}`, slug }
}

export function run(argv = [], { root } = {}) {
  const r = root ?? codeRoot()
  const libDir = join(r, "skills-library")
  const activeDir = join(r, ".claude", "skills")

  try {
    const [sub, ...rest] = argv
    const force = rest.includes("--force")
    const slug = rest.find((a) => !a.startsWith("--"))

    if (!sub || sub === "list") return listSkills({ libDir, activeDir })
    if (sub === "promote") return promoteSkill({ libDir, activeDir, slug, force })
    if (sub === "demote") return demoteSkill({ libDir, activeDir, slug })
    return { code: 1, message: `bh-skill: unknown subcommand "${sub}"\n\n${usage()}` }
  } catch (e) {
    return { code: 1, message: `bh-skill: error: ${e.message}` }
  }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here -- same argv-identity idiom as
// bh-report.mjs / bh-burp-scope.mjs / bh-exec.mjs / bh-engagement.mjs /
// bh-enum-map.mjs / bh-recon-map.mjs / bh-exploit-map.mjs / bh-findings.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const result = run(process.argv.slice(2))
  if (result.message) {
    if (result.code === 0) process.stdout.write(result.message + "\n")
    else process.stderr.write(result.message + "\n")
  }
  process.exit(result.code)
}
