// test/manifest.test.mjs
//
// P6: plugin.json + hooks/hooks.json + marketplace.json are valid JSON and
// declare the expected components (spec §3, §4 P6). This is a static
// structural check on the packaging files themselves, not a runtime plugin
// load — Claude Code's own loader is exercised by actually installing the
// plugin (out of scope for `bun test`).
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..")

function readJson(relPath) {
  const raw = readFileSync(join(repoRoot, relPath), "utf8")
  return JSON.parse(raw)
}

test("plugin.json parses as valid JSON", () => {
  expect(() => readJson(".claude-plugin/plugin.json")).not.toThrow()
})

test("plugin.json declares name boundhound", () => {
  const manifest = readJson(".claude-plugin/plugin.json")
  expect(manifest.name).toBe("boundhound")
})

test("plugin.json declares hooks", () => {
  const manifest = readJson(".claude-plugin/plugin.json")
  expect(manifest.hooks).toBeTruthy()
  expect(typeof manifest.hooks).toBe("string")
})

test("hooks/hooks.json parses as valid JSON", () => {
  expect(() => readJson("hooks/hooks.json")).not.toThrow()
})

test("hooks/hooks.json PreToolUse command references ${CLAUDE_PLUGIN_ROOT}", () => {
  const hooks = readJson("hooks/hooks.json")
  const preToolUse = hooks.hooks.PreToolUse
  expect(Array.isArray(preToolUse)).toBe(true)
  const commands = preToolUse.flatMap((entry) => entry.hooks.map((h) => h.command))
  expect(commands.some((cmd) => cmd.includes("${CLAUDE_PLUGIN_ROOT}"))).toBe(true)
})

test("hooks/hooks.json PreToolUse matcher includes WebFetch", () => {
  const hooks = readJson("hooks/hooks.json")
  const matchers = hooks.hooks.PreToolUse.map((entry) => entry.matcher)
  expect(matchers.some((m) => m.includes("WebFetch"))).toBe(true)
})

test("marketplace.json parses as valid JSON", () => {
  expect(() => readJson(".claude-plugin/marketplace.json")).not.toThrow()
})

test("marketplace.json lists the boundhound plugin", () => {
  const marketplace = readJson(".claude-plugin/marketplace.json")
  expect(Array.isArray(marketplace.plugins)).toBe(true)
  expect(marketplace.plugins.some((p) => p.name === "boundhound")).toBe(true)
})
