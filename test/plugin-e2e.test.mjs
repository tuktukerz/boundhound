// test/plugin-e2e.test.mjs
//
// Real (unmocked) subprocess E2E for plugin mode (spec §4, E2E row). Proves
// the whole plugin-mode contract in one shot: the hook is invoked exactly as
// Claude Code would invoke it when installed as a plugin — code resolved via
// CLAUDE_PLUGIN_ROOT, state written under CLAUDE_PLUGIN_DATA — from a cwd
// that has nothing to do with the repo or the data dir. A denied bypass
// attempt must still be blocked (exit 2, permissionDecision "deny") AND its
// DENY line must land in the engagement's audit.log under the plugin data
// dir, not anywhere near the foreign cwd or the repo itself.
import { test, expect, beforeEach, afterEach } from "bun:test"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const hookPath = join(repoRoot, "hooks", "scope-guard.mjs")

const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope: { domains: ["api.acme.io"], cidrs: [] }
out_of_scope: { domains: [], cidrs: [] }
safety_constraints: { block_destructive: true, block_dos: true }
`

let pluginData, foreignCwd

beforeEach(() => {
  // Plugin data dir: where CLAUDE_PLUGIN_DATA would point once installed —
  // deliberately unrelated to the repo checkout.
  pluginData = mkdtempSync(join(tmpdir(), "boundhound-plugin-data-"))
  mkdirSync(join(pluginData, "engagements", "acme"), { recursive: true })
  writeFileSync(join(pluginData, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(pluginData, "engagements", ".active"), "acme")

  // Foreign cwd: a directory that is neither the repo nor the plugin data
  // dir, proving the hook depends on neither cwd nor CLAUDE_PROJECT_DIR.
  foreignCwd = mkdtempSync(join(tmpdir(), "boundhound-foreign-cwd-"))
})

afterEach(() => {
  rmSync(pluginData, { recursive: true, force: true })
  rmSync(foreignCwd, { recursive: true, force: true })
})

test("plugin mode: denied bypass from a foreign cwd is blocked and audited under CLAUDE_PLUGIN_DATA", () => {
  const event = JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl https://evil.com" } })

  const r = spawnSync("node", [hookPath], {
    cwd: foreignCwd,
    input: event,
    encoding: "utf8",
    env: {
      ...process.env,
      CLAUDE_PLUGIN_ROOT: repoRoot,
      CLAUDE_PLUGIN_DATA: pluginData,
    },
  })

  expect(r.status).toBe(2)
  expect(r.stdout).toContain('"permissionDecision":"deny"')

  const auditPath = join(pluginData, "engagements", "acme", "audit.log")
  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const entry = JSON.parse(lines[lines.length - 1])
  expect(entry.decision).toBe("DENY")
  expect(entry.tool.startsWith("hook:")).toBe(true)
})
