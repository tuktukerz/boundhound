// bin/bh-report.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runReport } from "./bh-report.mjs"

const now = () => "2026-08-25T00:00:00.000Z"

let root, engagementDir, outputDir

const VALID_SCOPE = `
engagement: acme
authorization: "acme SOW ref #123"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains:
    - acme.io
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: ""
`

// Missing "authorization:" -> parseScope's ScopeError("missing authorization").
const BROKEN_SCOPE = `
engagement: acme
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: []
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
`

const FINDINGS = {
  generated_at: "2026-08-25T00:00:00.000Z",
  findings: [
    {
      id: "aaaaaaaa",
      category: "exploit",
      type: "sqli",
      target: "acme.io",
      severity: "high",
      confidence: "confirmed",
      evidence: { dbms: "MySQL >= 5.6", injection_points: [] },
      verified: true,
    },
    {
      id: "bbbbbbbb",
      category: "recon",
      type: "open-port",
      target: "acme.io",
      severity: "info",
      confidence: "reported",
      evidence: { port: 22, proto: "tcp", service: "ssh" },
      verified: false,
    },
  ],
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-report-"))
  engagementDir = join(root, "engagements", "acme")
  outputDir = join(engagementDir, "output")
  mkdirSync(outputDir, { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
})

function writeScope(text) {
  writeFileSync(join(engagementDir, "scope.yaml"), text)
}

function writeFindings(obj) {
  const dir = join(outputDir, "verify")
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, "findings.json"), JSON.stringify(obj))
}

test("valid scope + findings.json -> writes report.md with engagement, a finding's target, and remediation", () => {
  writeScope(VALID_SCOPE)
  writeFindings(FINDINGS)

  const r = runReport({ dataDir: root, now })

  expect(r.code).toBe(0)
  const outPath = join(outputDir, "report", "report.md")
  expect(existsSync(outPath)).toBe(true)
  const md = readFileSync(outPath, "utf8")
  expect(md).toContain("acme")
  expect(md).toContain("acme.io")
  expect(md).toContain("Use parameterized queries")
})

test("audit.log ALLOW/DENY lines are summarized in the report appendix", () => {
  writeScope(VALID_SCOPE)
  writeFindings(FINDINGS)
  const auditLines = [
    JSON.stringify({ ts: "t1", target: "acme.io", tool: "nmap", decision: "ALLOW", reason: "in_scope:acme.io", authorization: "x" }),
    JSON.stringify({ ts: "t2", target: "acme.io", tool: "httpx", decision: "ALLOW", reason: "in_scope:acme.io", authorization: "x" }),
    JSON.stringify({ ts: "t3", target: "evil.com", tool: "nmap", decision: "DENY", reason: "out_of_scope:evil.com", authorization: "x" }),
  ]
  writeFileSync(join(engagementDir, "audit.log"), auditLines.join("\n") + "\n")

  const r = runReport({ dataDir: root, now })
  expect(r.code).toBe(0)
  const md = readFileSync(join(outputDir, "report", "report.md"), "utf8")
  expect(md).toContain("2 ALLOW")
  expect(md).toContain("1 DENY")
})

test("broken scope.yaml -> fail-closed code 3, no report.md written", () => {
  writeScope(BROKEN_SCOPE)
  writeFindings(FINDINGS)

  const r = runReport({ dataDir: root, now })
  expect(r.code).toBe(3)
  expect(existsSync(join(outputDir, "report", "report.md"))).toBe(false)
})

test("missing scope.yaml entirely -> fail-closed code 3, no report.md written", () => {
  writeFindings(FINDINGS)

  const r = runReport({ dataDir: root, now })
  expect(r.code).toBe(3)
  expect(existsSync(join(outputDir, "report", "report.md"))).toBe(false)
})

test("missing findings.json (valid scope) -> still writes a valid 'no findings' report, code 0", () => {
  writeScope(VALID_SCOPE)

  const r = runReport({ dataDir: root, now })
  expect(r.code).toBe(0)
  const md = readFileSync(join(outputDir, "report", "report.md"), "utf8")
  expect(md).toContain("No findings recorded.")
})

test("invalid/corrupt findings.json is treated as missing, not a crash", () => {
  writeScope(VALID_SCOPE)
  mkdirSync(join(outputDir, "verify"), { recursive: true })
  writeFileSync(join(outputDir, "verify", "findings.json"), "{not valid json")

  const r = runReport({ dataDir: root, now })
  expect(r.code).toBe(0)
  const md = readFileSync(join(outputDir, "report", "report.md"), "utf8")
  expect(md).toContain("No findings recorded.")
})

test("no active engagement -> fail-closed code 3, no output written", () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-report-bare-"))
  const r = runReport({ dataDir: bareRoot, now })
  expect(r.code).toBe(3)
  expect(existsSync(join(bareRoot, "engagements"))).toBe(false)
})
