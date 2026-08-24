import { test, expect } from "bun:test"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { decideFromEvent } from "./scope-guard.mjs"

const hookPath = fileURLToPath(new URL("./scope-guard.mjs", import.meta.url))
function runHook(stdin) {
  const r = spawnSync("node", [hookPath], { input: stdin, encoding: "utf8" })
  return { status: r.status, stdout: r.stdout }
}

test("non-Bash tool -> allow (not our concern)", () => {
  expect(decideFromEvent({ tool_name: "Read", tool_input: {} }).hookSpecificOutput.permissionDecision).toBe("allow")
})
test("Bash direct curl -> deny", () => {
  expect(decideFromEvent({ tool_name: "Bash", tool_input: { command: "curl https://evil.com" } }).hookSpecificOutput.permissionDecision).toBe("deny")
})
test("Bash via omop-exec -> allow", () => {
  expect(decideFromEvent({ tool_name: "Bash", tool_input: { command: "omop-exec curl --target x" } }).hookSpecificOutput.permissionDecision).toBe("allow")
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
test("cli: omop-exec -> allow + exit 0", () => {
  const r = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "omop-exec curl --target x" } }))
  expect(r.status).toBe(0)
  expect(r.stdout).toContain('"permissionDecision":"allow"')
})
