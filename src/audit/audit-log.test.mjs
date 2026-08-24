import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { appendAudit } from "./audit-log.mjs"

let dir
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "bh-audit-")) })

test("appends a JSON line with all fields", () => {
  const p = join(dir, "audit.log")
  appendAudit(p, { ts: "2026-08-24T00:00:00Z", target: "api.acme.io", tool: "curl", decision: "ALLOW", reason: "in_scope", authorization: "H1 #1" })
  appendAudit(p, { ts: "2026-08-24T00:00:01Z", target: "evil.com", tool: "curl", decision: "DENY", reason: "deny-by-default", authorization: "H1 #1" })
  const lines = readFileSync(p, "utf8").trim().split("\n")
  expect(lines.length).toBe(2)
  const first = JSON.parse(lines[0])
  expect(first.decision).toBe("ALLOW")
  expect(first.authorization).toBe("H1 #1")
})
