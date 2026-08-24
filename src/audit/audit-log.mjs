import { appendFileSync } from "node:fs"

export function appendAudit(logPath, entry) {
  const line = JSON.stringify({
    ts: entry.ts,
    target: entry.target,
    tool: entry.tool,
    decision: entry.decision,
    reason: entry.reason,
    authorization: entry.authorization ?? null,
  })
  appendFileSync(logPath, line + "\n")
}
