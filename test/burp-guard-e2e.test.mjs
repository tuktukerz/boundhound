// test/burp-guard-e2e.test.mjs
//
// REAL end-to-end test for Phase 8's Burp MCP scope choke point (spec §7 E2E
// row). NO Burp Suite is needed and NOTHING here is mocked: this spins up a
// real temp --data-dir engagement (a real engagements/.active pointer plus a
// real scope.yaml parsed by the real scope parser), then drives the REAL
// hooks/scope-guard.mjs PreToolUse hook and the REAL bin/bh-burp-scope.mjs
// CLI as real child processes -- exactly as Claude Code's harness (for the
// hook) and an operator (for the CLI) would -- with real Burp-MCP-shaped
// tool-call events on stdin.
//
// Mirrors hooks/scope-guard.test.mjs's spawnSync + CLAUDE_PROJECT_DIR
// pattern: dataRoot() (src/paths.mjs) resolves
// CLAUDE_PLUGIN_DATA ?? CLAUDE_PROJECT_DIR ?? process.cwd(), and the
// existing hook tests point it at a temp engagement dir via the
// CLAUDE_PROJECT_DIR env var on the spawned subprocess -- so the same env
// var is used here to make our temp engagement the "active" one the hook
// reads. bin/bh-burp-scope.mjs takes the data dir directly via a
// "--data-dir" flag (bin/bh-burp-scope.test.mjs's pattern), so no env var is
// needed for that half.
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const hookPath = join(repoRoot, "hooks", "scope-guard.mjs")
const burpScopeBin = join(repoRoot, "bin", "bh-burp-scope.mjs")

const ENG_NAME = "acme"
const IN_SCOPE_DOMAIN = "acme.io"
const OUT_OF_SCOPE_DOMAIN = "blog.acme.com"

const SCOPE_YAML = `
engagement: ${ENG_NAME}
authorization: "acme SOW ref #e2e-burp-guard"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains:
    - ${IN_SCOPE_DOMAIN}
  cidrs: []
out_of_scope:
  domains:
    - ${OUT_OF_SCOPE_DOMAIN}
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: "burp-guard-e2e.test.mjs scaffolded engagement"
`

// Real hook subprocess -- same idiom as hooks/scope-guard.test.mjs's
// runHook(), parameterized on the data dir so each call can point
// CLAUDE_PROJECT_DIR (dataRoot()'s fallback) at whichever temp engagement
// dir that particular assertion needs.
function runHook(event, dataDir) {
  const r = spawnSync("node", [hookPath], {
    input: JSON.stringify(event),
    encoding: "utf8",
    env: { ...process.env, CLAUDE_PROJECT_DIR: dataDir },
  })
  return { status: r.status, stdout: r.stdout }
}

function decision(r) {
  return JSON.parse(r.stdout).hookSpecificOutput.permissionDecision
}

let dataDir

beforeAll(() => {
  dataDir = mkdtempSync(join(tmpdir(), "burp-guard-e2e-"))
  mkdirSync(join(dataDir, "engagements", ENG_NAME), { recursive: true })
  writeFileSync(join(dataDir, "engagements", ENG_NAME, "scope.yaml"), SCOPE_YAML)
  writeFileSync(join(dataDir, "engagements", ".active"), ENG_NAME)
})

// Fail-safe cleanup even if an assertion above throws mid-suite.
afterAll(() => {
  if (dataDir) rmSync(dataDir, { recursive: true, force: true })
})

// --- 1. Out-of-scope Burp call -> DENY (exit 2), audited with the Burp target ---

test("real hook: out-of-scope Burp MCP call -> deny (exit 2) + audited with the Burp target", () => {
  const target = `http://${OUT_OF_SCOPE_DOMAIN}/x`
  const r = runHook({ tool_name: "mcp__burp__send_request", tool_input: { url: target } }, dataDir)

  expect(r.status).toBe(2)
  expect(decision(r)).toBe("deny")

  const auditPath = join(dataDir, "engagements", ENG_NAME, "audit.log")
  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const entry = JSON.parse(lines[lines.length - 1])
  expect(entry.decision).toBe("DENY")
  expect(entry.tool).toBe("hook:mcp__burp__send_request")
  expect(entry.target).toBe(target)
})

// --- 2. In-scope Burp call -> ALLOW (exit 0) ---

test("real hook: in-scope Burp MCP call -> allow (exit 0)", () => {
  const target = `http://${IN_SCOPE_DOMAIN}/x`
  const r = runHook({ tool_name: "mcp__burp__send_request", tool_input: { url: target } }, dataDir)

  expect(r.status).toBe(0)
  expect(decision(r)).toBe("allow")
})

// --- 3. No active engagement -> DENY (fail-closed, nothing to check against) ---

test("real hook: no active engagement -> deny (fail-closed)", () => {
  const bareDir = mkdtempSync(join(tmpdir(), "burp-guard-e2e-bare-"))
  try {
    const r = runHook(
      { tool_name: "mcp__burp__send_request", tool_input: { url: `http://${IN_SCOPE_DOMAIN}/x` } },
      bareDir,
    )
    expect(r.status).toBe(2)
    expect(decision(r)).toBe("deny")
  } finally {
    rmSync(bareDir, { recursive: true, force: true })
  }
})

// --- 4. Ambiguous / unresolvable Burp target -> DENY ---

test("real hook: ambiguous Burp target (disagreeing url/host fields) -> deny", () => {
  const r = runHook(
    {
      tool_name: "mcp__burp__send_request",
      tool_input: { url: `http://${IN_SCOPE_DOMAIN}`, host: OUT_OF_SCOPE_DOMAIN },
    },
    dataDir,
  )
  expect(r.status).toBe(2)
  expect(decision(r)).toBe("deny")
})

test("real hook: unresolvable Burp target (no target field at all) -> deny", () => {
  const r = runHook({ tool_name: "mcp__burp__send_request", tool_input: {} }, dataDir)
  expect(r.status).toBe(2)
  expect(decision(r)).toBe("deny")
})

// --- 5. Uppercase tool name is still guarded end to end (case-insensitive matcher) ---

test("real hook: uppercase 'mcp__BURP__...' tool name is still guarded -> deny for an out-of-scope target", () => {
  const r = runHook(
    { tool_name: "mcp__BURP__send_request", tool_input: { url: `http://${OUT_OF_SCOPE_DOMAIN}/x` } },
    dataDir,
  )
  expect(r.status).toBe(2)
  expect(decision(r)).toBe("deny")
})

// --- 6. Scope mirror: real bh-burp-scope.mjs CLI produces a Burp Target Scope ---

test("real CLI: bh-burp-scope mirrors the same engagement's scope.yaml into a Burp Target Scope", () => {
  const r = spawnSync("node", [burpScopeBin, "--data-dir", dataDir], { encoding: "utf8" })
  expect(r.status).toBe(0)

  const parsed = JSON.parse(r.stdout)
  expect(parsed.target.scope.include).toContainEqual({
    enabled: true,
    host: "^acme\\.io$",
    protocol: "any",
  })
  expect(parsed.target.scope.exclude).toContainEqual({
    enabled: true,
    host: "^blog\\.acme\\.com$",
    protocol: "any",
  })

  const outPath = join(dataDir, "engagements", ENG_NAME, "output", "burp", "target-scope.json")
  expect(existsSync(outPath)).toBe(true)
  expect(readFileSync(outPath, "utf8")).toBe(r.stdout)
})
