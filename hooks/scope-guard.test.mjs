import { test, expect } from "bun:test"
import { decideFromEvent } from "./scope-guard.mjs"

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
