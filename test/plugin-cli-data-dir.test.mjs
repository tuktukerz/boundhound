// test/plugin-cli-data-dir.test.mjs
//
// Targeted fix for Phase 0.5: the plugin-mode DATA directory didn't resolve
// correctly when the agent invokes the CLI. ${CLAUDE_PLUGIN_DATA} is only
// exported as a real env var to hook/MCP/LSP subprocesses (proven by
// test/plugin-e2e.test.mjs for the hook) — NOT to the agent's Bash tool
// session. So `node "${CLAUDE_PLUGIN_ROOT}/bin/bh-exec.mjs" ...`, run the
// way an agent actually runs it (via Bash), never saw CLAUDE_PLUGIN_DATA in
// its own process env, and dataRoot() silently fell through to cwd instead
// of the plugin's data dir.
//
// The fix threads the (content-substituted, per plugins-reference.md's
// "Skill and agent content" row) ${CLAUDE_PLUGIN_DATA} value through
// explicitly as a `--data-dir <path>` CLI argument. This is a REAL
// subprocess E2E (not a call into the exported runExec()) because the new
// code under test is the argv-parsing in bh-exec.mjs's `isMain` block,
// which only runs in the actual CLI entrypoint — see test/plugin-e2e.test.mjs
// for the same real-subprocess pattern applied to the hook.
import { test, expect, beforeEach, afterEach } from "bun:test"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const execPath = join(repoRoot, "bin", "bh-exec.mjs")

// out_of_scope target -> deterministic DENY, no docker/exec involved at all
// (the audit line is appended before the runner ever gets called), so these
// tests need nothing beyond Node itself.
const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope: { domains: ["api.acme.io"], cidrs: [] }
out_of_scope: { domains: ["evil.com"], cidrs: [] }
safety_constraints: { block_destructive: true, block_dos: true }
`

// Strip the two env vars dataRoot() would otherwise fall back to, so the
// only remaining way to point the CLI at pluginData is the new --data-dir
// flag (or, for the fallback test, cwd itself).
function envWithoutPluginData() {
  const env = { ...process.env }
  delete env.CLAUDE_PLUGIN_DATA
  delete env.CLAUDE_PROJECT_DIR
  return env
}

let pluginData, foreignCwd

beforeEach(() => {
  pluginData = mkdtempSync(join(tmpdir(), "boundhound-cli-data-"))
  foreignCwd = mkdtempSync(join(tmpdir(), "boundhound-cli-foreign-cwd-"))
})

afterEach(() => {
  rmSync(pluginData, { recursive: true, force: true })
  rmSync(foreignCwd, { recursive: true, force: true })
})

test("plugin-mode CLI: --data-dir routes state/audit to the passed dir, not cwd", () => {
  // pluginData holds the active engagement; foreignCwd is left completely
  // empty (no engagements/ at all). If the CLI ignored --data-dir and fell
  // back to cwd (the bug), loadActiveConfig would find nothing under
  // foreignCwd and fail-closed with exit 3 (NoActiveEngagement) instead of
  // the exit 2 DENY this test expects — so exit 2 is proof --data-dir won.
  mkdirSync(join(pluginData, "engagements", "acme"), { recursive: true })
  writeFileSync(join(pluginData, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(pluginData, "engagements", ".active"), "acme")

  const r = spawnSync(
    "node",
    [execPath, "curl", "--target", "evil.com", "--data-dir", pluginData, "--"],
    { cwd: foreignCwd, encoding: "utf8", env: envWithoutPluginData() },
  )

  expect(r.status).toBe(2)
  expect(r.stderr).toContain("DENY")

  const auditPath = join(pluginData, "engagements", "acme", "audit.log")
  expect(existsSync(auditPath)).toBe(true)
  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const entry = JSON.parse(lines[lines.length - 1])
  expect(entry.decision).toBe("DENY")
  expect(entry.target).toBe("evil.com")

  // Nothing should have landed under the foreign cwd — proves the audit
  // trail didn't split between the hook's data dir and the CLI's.
  expect(existsSync(join(foreignCwd, "engagements"))).toBe(false)
})

test("plugin-mode CLI: without --data-dir and env unset, falls back to cwd (documents the fallback)", () => {
  // No --data-dir passed, and CLAUDE_PLUGIN_DATA/CLAUDE_PROJECT_DIR are both
  // unset, so dataRoot()'s only remaining fallback is process.cwd(). Seed
  // the active engagement directly under foreignCwd (standing in for cwd)
  // to prove that's genuinely where the CLI looked.
  mkdirSync(join(foreignCwd, "engagements", "acme"), { recursive: true })
  writeFileSync(join(foreignCwd, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(foreignCwd, "engagements", ".active"), "acme")

  const r = spawnSync(
    "node",
    [execPath, "curl", "--target", "evil.com", "--"],
    { cwd: foreignCwd, encoding: "utf8", env: envWithoutPluginData() },
  )

  expect(r.status).toBe(2)
  expect(r.stderr).toContain("DENY")

  const auditPath = join(foreignCwd, "engagements", "acme", "audit.log")
  expect(existsSync(auditPath)).toBe(true)
  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const entry = JSON.parse(lines[lines.length - 1])
  expect(entry.decision).toBe("DENY")

  // pluginData (unused in this test) must stay untouched — nothing here
  // should have been written there.
  expect(existsSync(join(pluginData, "engagements"))).toBe(false)
})
