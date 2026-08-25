// bin/bh-burp-scope.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runBurpScope, buildBurpScope, domainToHostRegex } from "./bh-burp-scope.mjs"

const binPath = fileURLToPath(new URL("./bh-burp-scope.mjs", import.meta.url))

let root, engagementDir, outputPath

const VALID_SCOPE = `
engagement: acme
authorization: "acme SOW ref #123"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains:
    - acme.io
    - "*.acme.com"
  cidrs:
    - 10.0.0.0/24
out_of_scope:
  domains:
    - evil.acme.io
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: ""
`

// Missing "authorization:" -> parseScope's ScopeError("missing authorization"),
// same fixture bh-report.test.mjs / bh-fullscan.test.mjs use for the broken-
// scope fail-closed case.
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

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-burp-scope-"))
  engagementDir = join(root, "engagements", "acme")
  mkdirSync(engagementDir, { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
  outputPath = join(engagementDir, "output", "burp", "target-scope.json")
})

function writeScope(text) {
  writeFileSync(join(engagementDir, "scope.yaml"), text)
}

// --- pure mapping helpers -----------------------------------------------

test("domainToHostRegex: a plain domain maps to an anchored, exact-match host regex", () => {
  expect(domainToHostRegex("acme.io")).toBe("^acme\\.io$")
})

test("domainToHostRegex: a wildcard domain maps to a subdomain-inclusive host regex", () => {
  expect(domainToHostRegex("*.acme.com")).toBe("^(.*\\.)?acme\\.com$")
})

test("domainToHostRegex: escapes regex metacharacters in the literal part", () => {
  // Only "." can appear in a validated domain, but the escaper must not
  // rely on that -- assert the "." is escaped so it matches a literal dot,
  // not "any character".
  const re = new RegExp(domainToHostRegex("acme.io"))
  expect(re.test("acmeXio")).toBe(false)
  expect(re.test("acme.io")).toBe(true)
})

test("buildBurpScope: maps in_scope domains/cidrs to include, out_of_scope to exclude", () => {
  const scope = buildBurpScope({
    in_scope: { domains: ["acme.io", "*.acme.com"], cidrs: ["10.0.0.0/24"] },
    out_of_scope: { domains: ["evil.acme.io"], cidrs: [] },
  })

  expect(scope.target.scope.include).toEqual([
    { enabled: true, host: "^acme\\.io$", protocol: "any" },
    { enabled: true, host: "^(.*\\.)?acme\\.com$", protocol: "any" },
    { enabled: true, host: "10.0.0.0/24", protocol: "any" },
  ])
  expect(scope.target.scope.exclude).toEqual([
    { enabled: true, host: "^evil\\.acme\\.io$", protocol: "any" },
  ])
})

// --- runBurpScope (exported fn, same testability pattern as runReport) --

test("valid scope -> writes output/burp/target-scope.json with correct include/exclude entries", () => {
  writeScope(VALID_SCOPE)

  const r = runBurpScope({ dataDir: root })

  expect(r.code).toBe(0)
  expect(existsSync(outputPath)).toBe(true)
  const written = JSON.parse(readFileSync(outputPath, "utf8"))
  expect(written.target.scope.include).toEqual([
    { enabled: true, host: "^acme\\.io$", protocol: "any" },
    { enabled: true, host: "^(.*\\.)?acme\\.com$", protocol: "any" },
    { enabled: true, host: "10.0.0.0/24", protocol: "any" },
  ])
  expect(written.target.scope.exclude).toEqual([
    { enabled: true, host: "^evil\\.acme\\.io$", protocol: "any" },
  ])
})

test("runBurpScope is deterministic: two runs produce byte-identical file content", () => {
  writeScope(VALID_SCOPE)

  const r1 = runBurpScope({ dataDir: root })
  const bytes1 = readFileSync(outputPath, "utf8")
  const r2 = runBurpScope({ dataDir: root })
  const bytes2 = readFileSync(outputPath, "utf8")

  expect(r1.code).toBe(0)
  expect(r2.code).toBe(0)
  expect(bytes1).toBe(bytes2)
  expect(r1.json).toBe(r2.json)
})

test("broken scope.yaml -> fail-closed code 3, nothing written", () => {
  writeScope(BROKEN_SCOPE)

  const r = runBurpScope({ dataDir: root })
  expect(r.code).toBe(3)
  expect(existsSync(outputPath)).toBe(false)
})

test("missing scope.yaml entirely -> fail-closed code 3, nothing written", () => {
  const r = runBurpScope({ dataDir: root })
  expect(r.code).toBe(3)
  expect(existsSync(outputPath)).toBe(false)
})

test("no active engagement -> fail-closed code 3, nothing written", () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-burp-scope-bare-"))
  const r = runBurpScope({ dataDir: bareRoot })
  expect(r.code).toBe(3)
  expect(existsSync(join(bareRoot, "engagements"))).toBe(false)
})

// --- CLI subprocess (real process, mirrors hooks/scope-guard.test.mjs's
// spawnSync pattern) -- proves the actual stdout-printing + exit-code
// behavior wired up in the isMain block, not just the exported fn. --------

function runCli(dataDir) {
  const r = spawnSync("node", [binPath, "--data-dir", dataDir], { encoding: "utf8" })
  return { status: r.status, stdout: r.stdout, stderr: r.stderr }
}

test("CLI: valid scope -> exit 0, stdout is the Burp scope JSON, file also written", () => {
  writeScope(VALID_SCOPE)

  const r = runCli(root)
  expect(r.status).toBe(0)
  const parsed = JSON.parse(r.stdout)
  expect(parsed.target.scope.include.length).toBe(3)
  expect(parsed.target.scope.exclude.length).toBe(1)
  expect(existsSync(outputPath)).toBe(true)
  expect(readFileSync(outputPath, "utf8")).toBe(r.stdout)
})

test("CLI: run twice -> identical stdout bytes (deterministic)", () => {
  writeScope(VALID_SCOPE)

  const r1 = runCli(root)
  const r2 = runCli(root)
  expect(r1.stdout).toBe(r2.stdout)
})

test("CLI: broken/missing scope -> exit code 3, empty stdout, nothing written", () => {
  const r = runCli(root)
  expect(r.status).toBe(3)
  expect(r.stdout).toBe("")
  expect(existsSync(outputPath)).toBe(false)
})
