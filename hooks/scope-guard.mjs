import { fileURLToPath } from "node:url"
import { join } from "node:path"
import { classifyCommand } from "../src/guard/guard.mjs"
import { activeName } from "../src/scope/active-engagement.mjs"
import { appendAudit } from "../src/audit/audit-log.mjs"

const NETWORK_TOOLS = new Set(["WebFetch", "WebSearch"])
const SCOPE_FILE_RE = /engagements\/[^/]+\/scope\.yaml$/

export function decideFromEvent(event) {
  const mk = (decision, reason) => ({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision, // "allow" | "deny"
      permissionDecisionReason: reason,
    },
  })
  if (event.tool_name === "Bash") {
    const cmd = event.tool_input?.command ?? ""
    const r = classifyCommand(cmd)
    return mk(r.decision === "ALLOW" ? "allow" : "deny", r.reason)
  }
  if (NETWORK_TOOLS.has(event.tool_name)) {
    return mk("deny", `${event.tool_name} not yet threaded through scope enforcement (Fase 0) — use omop-exec`)
  }
  if ((event.tool_name === "Write" || event.tool_name === "Edit") && SCOPE_FILE_RE.test(event.tool_input?.file_path ?? "")) {
    return mk("deny", "scope.yaml is the trust root — edit only via /engagement or /mode, not directly")
  }
  return mk("allow", "not-network-tool")
}

// Best-effort audit of a hook-level DENY (an attempted bypass caught before
// omop-exec even ran). Allowed Bash commands are already audited by
// omop-exec itself when they take the sanctioned path, so only DENYs are
// logged here — auditing every allowed `git status`/`ls` would be noise.
// Failures here (no active engagement, unwritable audit log, etc.) must
// never change the hook's actual permission decision.
function auditHookDeny(rootDir, { tool, detail, reason }) {
  try {
    const name = activeName(rootDir)
    if (!name) return
    const auditPath = join(rootDir, "engagements", name, "audit.log")
    appendAudit(auditPath, {
      ts: new Date().toISOString(),
      target: detail ?? null,
      tool: `hook:${tool ?? "unknown"}`,
      decision: "DENY",
      reason,
      authorization: null,
    })
  } catch {
    // best-effort — never let audit logging break the hook's actual decision
  }
}

// CLI entry: read stdin JSON, emit decision. Runs only when executed directly.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const failClosed = (reason) => ({
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason },
  })
  let event = {}
  let out
  try {
    let input = ""
    process.stdin.setEncoding("utf8")
    for await (const chunk of process.stdin) input += chunk
    const parsed = JSON.parse(input || "{}")
    event = parsed && typeof parsed === "object" ? parsed : {}
    out = event.tool_name ? decideFromEvent(event) : failClosed("malformed hook event (fail-closed)")
  } catch {
    out = failClosed("hook error (fail-closed)")
  }
  if (out.hookSpecificOutput.permissionDecision === "deny") {
    auditHookDeny(process.env.CLAUDE_PROJECT_DIR ?? process.cwd(), {
      tool: event.tool_name,
      detail: event.tool_input?.command ?? event.tool_input?.file_path ?? event.tool_input?.url ?? null,
      reason: out.hookSpecificOutput.permissionDecisionReason,
    })
  }
  process.stdout.write(JSON.stringify(out))
  // Hardening: exit 2 on deny so the block holds even if the JSON schema drifts.
  process.exit(out.hookSpecificOutput.permissionDecision === "deny" ? 2 : 0)
}
