// test/manifest.test.mjs
//
// P6: plugin.json + hooks/hooks.json + marketplace.json are valid JSON and
// declare the expected components (spec §3, §4 P6). This is a static
// structural check on the packaging files themselves, not a runtime plugin
// load — Claude Code's own loader is exercised by actually installing the
// plugin (out of scope for `bun test`).
import { test, expect } from "bun:test"
import { readFileSync, existsSync } from "node:fs"
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

test("hooks/hooks.json PreToolUse matcher is the exact full tool set (core + Burp MCP)", () => {
  const hooks = readJson("hooks/hooks.json")
  const matchers = hooks.hooks.PreToolUse.map((entry) => entry.matcher)
  // Exact-match (not .includes) so a future narrowing of the matcher — e.g.
  // dropping to just "WebFetch", or losing the Burp MCP arm — fails loudly
  // instead of passing silently. The `mcp__.*[Bb]urp.*` arm (Phase 8) routes
  // Burp MCP tool calls through the scope guard (deny-by-default choke point).
  expect(matchers.some((m) => m === "Bash|WebFetch|WebSearch|Write|Edit|mcp__.*[Bb]urp.*")).toBe(true)
})

// Cross-check parity: dev-mode (.claude/settings.json, $CLAUDE_PROJECT_DIR)
// and plugin-mode (hooks/hooks.json, ${CLAUDE_PLUGIN_ROOT}) are two
// independently maintained copies of the SAME PreToolUse registration (spec
// §3: "Document the two-mode duplication so they don't drift"). The tests
// above each assert one file against a hardcoded literal, which would keep
// passing even if the two files drifted apart from each other as long as
// both still happened to match that literal today. This test instead checks
// the two files against EACH OTHER, so a future edit to either file's
// matcher that isn't mirrored in the other fails the suite immediately.
test("PreToolUse matcher is identical across dev-mode settings.json and plugin-mode hooks.json", () => {
  const settings = readJson(".claude/settings.json")
  const hooks = readJson("hooks/hooks.json")
  const settingsMatchers = settings.hooks.PreToolUse.map((entry) => entry.matcher)
  const hooksMatchers = hooks.hooks.PreToolUse.map((entry) => entry.matcher)
  expect(settingsMatchers).toEqual(hooksMatchers)
})

// P6 hardening: plugin.json's declared component paths must resolve to real
// files/dirs, not just be well-typed strings — a typo'd path would still
// pass the "declares hooks"/"is a string" checks above but silently fail to
// load anything once Claude Code actually installs the plugin.
test("plugin.json's declared skills/commands/hooks paths exist on disk", () => {
  const manifest = readJson(".claude-plugin/plugin.json")
  expect(existsSync(join(repoRoot, manifest.skills))).toBe(true)
  expect(existsSync(join(repoRoot, manifest.commands))).toBe(true)
  expect(existsSync(join(repoRoot, manifest.hooks))).toBe(true)
})

test("marketplace.json parses as valid JSON", () => {
  expect(() => readJson(".claude-plugin/marketplace.json")).not.toThrow()
})

test("marketplace.json lists the boundhound plugin", () => {
  const marketplace = readJson(".claude-plugin/marketplace.json")
  expect(Array.isArray(marketplace.plugins)).toBe(true)
  expect(marketplace.plugins.some((p) => p.name === "boundhound")).toBe(true)
})
