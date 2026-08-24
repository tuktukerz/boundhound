import { fileURLToPath } from "node:url"
import { classifyCommand } from "../src/guard/guard.mjs"

export function decideFromEvent(event) {
  const mk = (decision, reason) => ({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision, // "allow" | "deny"
      permissionDecisionReason: reason,
    },
  })
  if (event.tool_name !== "Bash") return mk("allow", "not-bash")
  const cmd = event.tool_input?.command ?? ""
  const r = classifyCommand(cmd)
  return mk(r.decision === "ALLOW" ? "allow" : "deny", r.reason)
}

// CLI entry: read stdin JSON, emit decision. Runs only when executed directly.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  let input = ""
  process.stdin.setEncoding("utf8")
  for await (const chunk of process.stdin) input += chunk
  const failClosed = (reason) => ({
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason },
  })
  let out
  try {
    const parsed = JSON.parse(input || "{}")
    const event = parsed && typeof parsed === "object" ? parsed : {}
    out = event.tool_name ? decideFromEvent(event) : failClosed("malformed hook event (fail-closed)")
  } catch {
    out = failClosed("hook error (fail-closed)")
  }
  process.stdout.write(JSON.stringify(out))
  // Hardening: exit 2 on deny so the block holds even if the JSON schema drifts.
  process.exit(out.hookSpecificOutput.permissionDecision === "deny" ? 2 : 0)
}
