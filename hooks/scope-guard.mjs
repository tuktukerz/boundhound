import { fileURLToPath } from "node:url"
import { join } from "node:path"
import { classifyCommand } from "../src/guard/guard.mjs"
import { activeName, loadActiveConfig } from "../src/scope/active-engagement.mjs"
import { isBurpMcpTool, extractBurpTarget, decideBurpMcp } from "../src/guard/burp-guard.mjs"
import { appendAudit } from "../src/audit/audit-log.mjs"
import { dataRoot } from "../src/paths.mjs"

const NETWORK_TOOLS = new Set(["WebFetch", "WebSearch"])
const SCOPE_FILE_RE = /engagements\/[^/]+\/scope\.yaml$/

// Real scope loader used by the CLI entry point (`isMain`, below). Burp MCP
// calls never pass through bh-exec, so this hook is the only place that
// enforces scope on them -- any failure here (no active engagement, missing
// or broken scope.yaml, etc.) MUST fail closed to "no scope available"
// rather than throw, so `decideBurpMcp` denies with "no-active-scope"
// instead of the hook crashing into an unhandled-rejection allow.
function defaultLoadScope() {
  try {
    return loadActiveConfig(dataRoot())
  } catch {
    return null
  }
}

export function decideFromEvent(event, { loadScope = defaultLoadScope } = {}) {
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
    return mk("deny", `${event.tool_name} not yet threaded through scope enforcement (Phase 0) — use bh-exec`)
  }
  if ((event.tool_name === "Write" || event.tool_name === "Edit") && SCOPE_FILE_RE.test(event.tool_input?.file_path ?? "")) {
    return mk("deny", "scope.yaml is the trust root — edit only via /engagement or /mode, not directly")
  }
  // Burp Suite runs on the host and issues its own HTTP requests, so Burp
  // MCP tool calls never pass through bh-exec's scope check -- this is the
  // only choke point for them (Phase 8 spec §2/§3). `loadScope` is injected
  // (defaulting to the real active-engagement loader above) purely so this
  // stays testable without touching disk; it is never called for any other
  // tool_name, so non-Burp decisions above are unaffected.
  if (isBurpMcpTool(event.tool_name)) {
    const scope = loadScope()
    const r = decideBurpMcp(event.tool_input, scope)
    return mk(r.decision === "ALLOW" ? "allow" : "deny", r.reason)
  }
  return mk("allow", "not-network-tool")
}

// Best-effort audit detail for a hook DENY: the Burp target for a Burp MCP
// tool call (so the audit line is meaningful — "denied a Bash command" vs.
// "denied a Burp call" both need to say *what* was targeted), else the
// existing command/file_path/url fields. This is evaluated as an argument to
// `auditHookDeny` — OUTSIDE that function's own try/catch — so it self-guards:
// `isBurpMcpTool`/`extractBurpTarget` are hardened to never throw (Task 1), but
// a stray throw here must never crash the hook and lose its decision, so the
// whole body is wrapped and falls back to null.
function hookDenyDetail(event) {
  try {
    if (isBurpMcpTool(event.tool_name)) return extractBurpTarget(event.tool_input)
    return event.tool_input?.command ?? event.tool_input?.file_path ?? event.tool_input?.url ?? null
  } catch {
    return null
  }
}

// Best-effort audit of a hook-level DENY (an attempted bypass caught before
// bh-exec even ran). Allowed Bash commands are already audited by
// bh-exec itself when they take the sanctioned path, so only DENYs are
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
    auditHookDeny(dataRoot(), {
      tool: event.tool_name,
      detail: hookDenyDetail(event),
      reason: out.hookSpecificOutput.permissionDecisionReason,
    })
  }
  process.stdout.write(JSON.stringify(out))
  // Hardening: exit 2 on deny so the block holds even if the JSON schema drifts.
  process.exit(out.hookSpecificOutput.permissionDecision === "deny" ? 2 : 0)
}
