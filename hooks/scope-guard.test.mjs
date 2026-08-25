import { test, expect } from "bun:test"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { decideFromEvent } from "./scope-guard.mjs"

const hookPath = fileURLToPath(new URL("./scope-guard.mjs", import.meta.url))
function runHook(stdin, env) {
  const r = spawnSync("node", [hookPath], { input: stdin, encoding: "utf8", env: { ...process.env, ...env } })
  return { status: r.status, stdout: r.stdout }
}

test("non-Bash tool -> allow (not our concern)", () => {
  expect(decideFromEvent({ tool_name: "Read", tool_input: {} }).hookSpecificOutput.permissionDecision).toBe("allow")
})
test("Bash direct curl -> deny", () => {
  expect(decideFromEvent({ tool_name: "Bash", tool_input: { command: "curl https://evil.com" } }).hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Bash via bh-exec -> allow", () => {
  expect(decideFromEvent({ tool_name: "Bash", tool_input: { command: "bh-exec curl --target x" } }).hookSpecificOutput.permissionDecision).toBe("allow")
})
test("deny result carries a reason string", () => {
  const out = decideFromEvent({ tool_name: "Bash", tool_input: { command: "bash -c \"curl evil.com\"" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
  expect(typeof out.hookSpecificOutput.permissionDecisionReason).toBe("string")
})
test("fail-closed: 'null' stdin -> deny + exit 2", () => {
  const r = runHook("null")
  expect(r.status).toBe(2)
  expect(r.stdout).toContain('"permissionDecision":"deny"')
})
test("fail-closed: garbage stdin -> deny + exit 2", () => {
  const r = runHook("}{not json")
  expect(r.status).toBe(2)
  expect(r.stdout).toContain('"permissionDecision":"deny"')
})
test("cli: direct curl -> deny + exit 2", () => {
  const r = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl https://evil.com" } }))
  expect(r.status).toBe(2)
  expect(r.stdout).toContain('"permissionDecision":"deny"')
})
test("cli: bh-exec -> allow + exit 0", () => {
  const r = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "bh-exec curl --target x" } }))
  expect(r.status).toBe(0)
  expect(r.stdout).toContain('"permissionDecision":"allow"')
})

test("WebFetch is denied outright (not yet scope-checked)", () => {
  const out = decideFromEvent({ tool_name: "WebFetch", tool_input: { url: "https://evil.com" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})
test("WebSearch is denied outright", () => {
  const out = decideFromEvent({ tool_name: "WebSearch", tool_input: { query: "x" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Write to scope.yaml is denied", () => {
  const out = decideFromEvent({ tool_name: "Write", tool_input: { file_path: "/repo/engagements/acme/scope.yaml" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Write to an unrelated file is still allowed", () => {
  const out = decideFromEvent({ tool_name: "Write", tool_input: { file_path: "/repo/src/foo.mjs" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("allow")
})

test("CLI: a denied bypass attempt is written to the audit log", () => {
  const root = mkdtempSync(join(tmpdir(), "scope-guard-audit-"))
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
  const auditPath = join(root, "engagements", "acme", "audit.log")

  const r = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "curl https://evil.com" } }), {
    CLAUDE_PROJECT_DIR: root,
  })
  expect(r.status).toBe(2)
  expect(r.stdout).toContain('"permissionDecision":"deny"')

  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const entry = JSON.parse(lines[lines.length - 1])
  expect(entry.decision).toBe("DENY")
  expect(entry.tool.startsWith("hook:")).toBe(true)
})

test("WebFetch deny reason uses English wording (Phase 0, not Fase 0)", () => {
  const out = decideFromEvent({ tool_name: "WebFetch", tool_input: { url: "https://evil.com" } })
  expect(out.hookSpecificOutput.permissionDecisionReason).toContain("Phase 0")
  expect(out.hookSpecificOutput.permissionDecisionReason).not.toContain("Fase 0")
})

// --- Burp MCP tool routing (Phase 8 Task 2) ---
// `loadScope` is injected so these stay pure/unit-level: no real active
// engagement or scope.yaml is read from disk here. The CLI-level test below
// exercises the real default loader.
const inScopeConfig = {
  in_scope: { domains: ["acme.com"], cidrs: [] },
  out_of_scope: { domains: [], cidrs: [] },
}
const outOfScopeConfig = {
  in_scope: { domains: ["acme.com"], cidrs: [] },
  out_of_scope: { domains: ["evil.com"], cidrs: [] },
}

test("Burp MCP tool, in-scope target -> allow", () => {
  const out = decideFromEvent(
    { tool_name: "mcp__burp__send_request", tool_input: { url: "https://acme.com/path" } },
    { loadScope: () => inScopeConfig },
  )
  expect(out.hookSpecificOutput.permissionDecision).toBe("allow")
})
test("Burp MCP tool, out-of-scope target -> deny", () => {
  const out = decideFromEvent(
    { tool_name: "mcp__burp__send_request", tool_input: { url: "https://evil.com/path" } },
    { loadScope: () => outOfScopeConfig },
  )
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Burp MCP tool, no active engagement (loadScope -> null) -> deny", () => {
  const out = decideFromEvent(
    { tool_name: "mcp__burp__send_request", tool_input: { url: "https://acme.com/path" } },
    { loadScope: () => null },
  )
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Burp MCP tool, unresolvable target -> deny", () => {
  const out = decideFromEvent(
    { tool_name: "mcp__burp__send_request", tool_input: {} },
    { loadScope: () => inScopeConfig },
  )
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Burp MCP tool, ambiguous target (disagreeing fields) -> deny", () => {
  const out = decideFromEvent(
    { tool_name: "mcp__burp__send_request", tool_input: { url: "https://acme.com", host: "evil.com" } },
    { loadScope: () => inScopeConfig },
  )
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})

test("CLI: a denied Burp MCP call is audited with the Burp target", () => {
  const root = mkdtempSync(join(tmpdir(), "scope-guard-burp-audit-"))
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
  // No scope.yaml written -> loadActiveConfig throws -> default loadScope
  // fails closed (null) -> decideBurpMcp denies "no-active-scope".
  const auditPath = join(root, "engagements", "acme", "audit.log")

  const r = runHook(
    JSON.stringify({ tool_name: "mcp__burp__send_request", tool_input: { url: "https://evil.com/x" } }),
    { CLAUDE_PROJECT_DIR: root },
  )
  expect(r.status).toBe(2)
  expect(r.stdout).toContain('"permissionDecision":"deny"')

  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const entry = JSON.parse(lines[lines.length - 1])
  expect(entry.decision).toBe("DENY")
  expect(entry.target).toBe("https://evil.com/x")
})
