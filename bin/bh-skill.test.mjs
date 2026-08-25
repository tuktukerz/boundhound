// bin/bh-skill.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { run, CORE_SKILLS } from "./bh-skill.mjs"

const binPath = fileURLToPath(new URL("./bh-skill.mjs", import.meta.url))

// Minimal-but-valid SKILL.md fixture -- same frontmatter shape as
// test/skill-library.test.mjs enforces (name === slug, description with a
// `Triggers:` clause, category, tags), so these fixtures would themselves
// pass that suite's per-skill checks.
function fakeSkillMd(slug, category, triggers) {
  return `---
name: ${slug}
description: "Fixture skill for bh-skill tests. Triggers: ${triggers}."
version: 1.0.0
phase: ["enum"]
category: ["${category}"]
tags: ["${slug}", "fixture"]
---

# ${slug}

## What it is
A fixture technique playbook used only by bin/bh-skill.test.mjs, wired to
bh-exec like every real skills-library entry.
`
}

const CORE_SKILL_MD = `---
name: pentest-recon
description: "Fixture core skill. Triggers: 'recon'."
version: 0.1.0
phase: ["recon"]
category: ["recon"]
tags: ["recon", "fixture"]
---

# Pentest Recon (fixture)

## What it is
A fixture standing in for the real core pentest-recon skill, wired to
bh-exec.
`

let root, libDir, activeDir

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-skill-"))
  libDir = join(root, "skills-library")
  activeDir = join(root, ".claude", "skills")

  mkdirSync(join(libDir, "fake-alpha"), { recursive: true })
  writeFileSync(join(libDir, "fake-alpha", "SKILL.md"), fakeSkillMd("fake-alpha", "web-injection", "'alpha test', 'alpha'"))

  mkdirSync(join(libDir, "fake-beta"), { recursive: true })
  writeFileSync(join(libDir, "fake-beta", "SKILL.md"), fakeSkillMd("fake-beta", "recon-osint", "'beta test', 'beta'"))

  mkdirSync(join(libDir, "fake-gamma"), { recursive: true })
  writeFileSync(join(libDir, "fake-gamma", "SKILL.md"), fakeSkillMd("fake-gamma", "api", "'gamma test', 'gamma'"))

  mkdirSync(join(activeDir, "pentest-recon"), { recursive: true })
  writeFileSync(join(activeDir, "pentest-recon", "SKILL.md"), CORE_SKILL_MD)
})

// --- CORE_SKILLS ------------------------------------------------------------

test("CORE_SKILLS is exactly the 8 always-active pipeline skills", () => {
  expect([...CORE_SKILLS].sort()).toEqual(
    [
      "pentest-recon",
      "pentest-enum",
      "pentest-exploit",
      "pentest-verify",
      "pentest-report",
      "pentest-workflow",
      "pentest-burp",
      "pentest-mode",
    ].sort()
  )
})

// --- list --------------------------------------------------------------------

test("list: reports every library slug with its category, none active yet", () => {
  const r = run(["list"], { root })
  expect(r.code).toBe(0)
  const slugs = r.skills.map((s) => s.slug)
  expect(slugs).toEqual(["fake-alpha", "fake-beta", "fake-gamma"])
  expect(r.skills.every((s) => s.active === false)).toBe(true)
  expect(r.skills.find((s) => s.slug === "fake-alpha").category).toBe("web-injection")
  expect(r.message).toContain("fake-alpha")
  expect(r.message).toContain("fake-beta")
  expect(r.message).toContain("fake-gamma")
})

test("list is the default subcommand when none is given", () => {
  const r = run([], { root })
  expect(r.code).toBe(0)
  expect(r.skills.map((s) => s.slug)).toEqual(["fake-alpha", "fake-beta", "fake-gamma"])
})

test("list marks a promoted skill as active, leaves the others inactive", () => {
  run(["promote", "fake-alpha"], { root })
  const r = run(["list"], { root })
  const alpha = r.skills.find((s) => s.slug === "fake-alpha")
  const beta = r.skills.find((s) => s.slug === "fake-beta")
  expect(alpha.active).toBe(true)
  expect(beta.active).toBe(false)
})

// --- promote -----------------------------------------------------------------

test("promote <slug>: copies the skill folder into .claude/skills/<slug>, content identical", () => {
  const r = run(["promote", "fake-alpha"], { root })
  expect(r.code).toBe(0)

  const destPath = join(activeDir, "fake-alpha", "SKILL.md")
  expect(existsSync(destPath)).toBe(true)
  expect(readFileSync(destPath, "utf8")).toBe(readFileSync(join(libDir, "fake-alpha", "SKILL.md"), "utf8"))
})

test("promote <slug>: confirmation names the skill and its Triggers", () => {
  const r = run(["promote", "fake-beta"], { root })
  expect(r.code).toBe(0)
  expect(r.message).toContain("fake-beta")
  expect(r.message).toContain("Triggers:")
  expect(r.message).toContain("beta test")
})

test("promote <unknown slug>: non-zero exit, nothing created", () => {
  const r = run(["promote", "does-not-exist"], { root })
  expect(r.code).not.toBe(0)
  expect(existsSync(join(activeDir, "does-not-exist"))).toBe(false)
})

test("promote with no slug: usage message, non-zero exit", () => {
  const r = run(["promote"], { root })
  expect(r.code).not.toBe(0)
  expect(r.message.toLowerCase()).toContain("usage")
})

test("promote an already-active slug: idempotent, exit 0, does not crash or re-copy needlessly", () => {
  run(["promote", "fake-alpha"], { root })
  const r = run(["promote", "fake-alpha"], { root })
  expect(r.code).toBe(0)
  expect(existsSync(join(activeDir, "fake-alpha", "SKILL.md"))).toBe(true)
})

test("promote --force on an already-active slug overwrites with the current library content", () => {
  run(["promote", "fake-alpha"], { root })
  // Simulate drift: the active copy no longer matches the library source.
  writeFileSync(join(activeDir, "fake-alpha", "SKILL.md"), "stale content")

  const r = run(["promote", "fake-alpha", "--force"], { root })
  expect(r.code).toBe(0)
  expect(readFileSync(join(activeDir, "fake-alpha", "SKILL.md"), "utf8")).toBe(
    readFileSync(join(libDir, "fake-alpha", "SKILL.md"), "utf8")
  )
})

// --- demote ------------------------------------------------------------------

test("demote <promoted slug>: removes .claude/skills/<slug>/", () => {
  run(["promote", "fake-alpha"], { root })
  expect(existsSync(join(activeDir, "fake-alpha"))).toBe(true)

  const r = run(["demote", "fake-alpha"], { root })
  expect(r.code).toBe(0)
  expect(existsSync(join(activeDir, "fake-alpha"))).toBe(false)
})

test("demote pentest-recon (CORE): refused, non-zero exit, folder still exists", () => {
  const r = run(["demote", "pentest-recon"], { root })
  expect(r.code).not.toBe(0)
  expect(existsSync(join(activeDir, "pentest-recon"))).toBe(true)
  expect(r.message.toLowerCase()).toContain("core")
})

test("demote every CORE skill by name is refused", () => {
  for (const slug of CORE_SKILLS) {
    const r = run(["demote", slug], { root })
    expect(r.code).not.toBe(0)
  }
})

test("demote a slug that isn't active: clear message, exit 0, doesn't crash", () => {
  const r = run(["demote", "fake-beta"], { root })
  expect(r.code).toBe(0)
  expect(r.message.toLowerCase()).toContain("not active")
})

test("demote refuses an active skill with no matching skills-library entry (can't be restored)", () => {
  // A skill folder that is active but was never promoted from this library
  // (e.g. hand-authored) must not be deletable by this tool -- there would
  // be nothing in skills-library/ to restore it from.
  mkdirSync(join(activeDir, "rogue-skill"), { recursive: true })
  writeFileSync(join(activeDir, "rogue-skill", "SKILL.md"), fakeSkillMd("rogue-skill", "recon", "'rogue'"))

  const r = run(["demote", "rogue-skill"], { root })
  expect(r.code).not.toBe(0)
  expect(existsSync(join(activeDir, "rogue-skill"))).toBe(true)
})

test("demote with no slug: usage message, non-zero exit", () => {
  const r = run(["demote"], { root })
  expect(r.code).not.toBe(0)
  expect(r.message.toLowerCase()).toContain("usage")
})

// --- unknown subcommand -------------------------------------------------------

test("unknown subcommand: usage message, non-zero exit", () => {
  const r = run(["frobnicate"], { root })
  expect(r.code).not.toBe(0)
  expect(r.message.toLowerCase()).toContain("usage")
})

// --- CLI subprocess (real process, mirrors bh-burp-scope.test.mjs's
// spawnSync pattern) -- read-only "list" against the REAL repo (codeRoot()
// falls back to this module's own repo location when no --data-dir-style
// root override is given), so it is safe to run without a temp root: it
// only reads skills-library/ and .claude/skills/, never writes. ------------

function runCli(args) {
  const r = spawnSync("node", [binPath, ...args], { encoding: "utf8" })
  return { status: r.status, stdout: r.stdout, stderr: r.stderr }
}

test("CLI: `list` against the real repo exits 0 and lists a known library skill", () => {
  const r = runCli(["list"])
  expect(r.status).toBe(0)
  expect(r.stdout).toContain("sqli")
})

test("CLI: unknown subcommand exits non-zero with a usage message on stderr", () => {
  const r = runCli(["frobnicate"])
  expect(r.status).not.toBe(0)
  expect(r.stderr.toLowerCase()).toContain("usage")
})

// Slug guard (defense-in-depth): a slug must be a plain kebab name, never a
// path. Traversal-shaped slugs are rejected before any copy/remove happens.
for (const bad of ["../foo", "..", "a/b", "foo/", "Foo", "a b", "../../etc"]) {
  test(`promote rejects invalid slug ${JSON.stringify(bad)}`, () => {
    const r = run(["promote", bad], { root })
    expect(r.code).toBe(1)
    expect(r.message.toLowerCase()).toContain("valid skill name")
  })
  test(`demote rejects invalid slug ${JSON.stringify(bad)} and deletes nothing`, () => {
    const r = run(["demote", bad], { root })
    expect(r.code).toBe(1)
    expect(r.message.toLowerCase()).toContain("valid skill name")
  })
}
