// bin/omop-exec.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runExec } from "./omop-exec.mjs"

let root, calls
const now = () => "2026-08-24T00:00:00Z"
const exec = (arr) => { calls.push(arr); return 0 }

function setup(scope) {
  root = mkdtempSync(join(tmpdir(), "omop-exec-"))
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(root, "engagements", ".active"), "acme")
  // catalog: copy the repo's for curl (must actually declare the flags the
  // tests pass through extraArgs, since runExec now rejects any extraArgs
  // token that isn't a declared flag — see the target-smuggling fix).
  writeFileSync(join(root, "tools-catalog.json"), JSON.stringify({
    version: "0", tools: [{ tools_name: "curl", description: "d", category: "utility",
      command: { base: "curl", flags: [{ name: "-sS" }, { name: "-I" }], positional: [{ name: "url", required: true }] }, phase: ["utility"] }]
  }))
  calls = []
}

const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["api.acme.io"]
out_of_scope:
  domains: ["blog.acme.com"]
safety_constraints: { block_destructive: true, block_dos: true }
`

beforeEach(() => setup(scope))

test("in-scope target -> exec + exit 0", () => {
  const r = runExec(["curl", "--target", "api.acme.io", "--", "-I"], { rootDir: root, now, exec })
  expect(r.code).toBe(0)
  expect(calls.length).toBe(1)
  expect(calls[0]).toContain("api.acme.io")
})

test("out-of-scope target -> DENY exit 2, no exec", () => {
  const r = runExec(["curl", "--target", "evil.com", "--"], { rootDir: root, now, exec })
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
})

test("destructive arg -> DENY exit 2", () => {
  const r = runExec(["curl", "--target", "api.acme.io", "--", "--os-shell"], { rootDir: root, now, exec })
  expect(r.code).toBe(2)
})

test("passes through tool non-zero exit code", () => {
  const failExec = () => 7
  const r = runExec(["curl", "--target", "api.acme.io", "--", "-I"], { rootDir: root, now, exec: failExec })
  expect(r.code).toBe(7)
})

test("catalog error -> DENY exit 2 (no throw)", () => {
  rmSync(join(root, "tools-catalog.json"))
  const r = runExec(["curl", "--target", "api.acme.io", "--"], { rootDir: root, now, exec })
  expect(r.code).toBe(2)
})

test("extraArgs cannot smuggle an alternate target past the declared flags", () => {
  const r = runExec(["curl", "--target", "api.acme.io", "--", "https://evil.com"], { rootDir: root, now, exec })
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
})
test("declared flags still work normally", () => {
  const r = runExec(["curl", "--target", "api.acme.io", "--", "-I"], { rootDir: root, now, exec })
  expect(r.code).toBe(0)
})

// P3: split codeDir/dataDir must behave identically to the single-rootDir
// case above — same ALLOW/DENY decisions, audit still lands under dataDir.
function setupSplit(scope) {
  const codeDir = mkdtempSync(join(tmpdir(), "omop-exec-code-"))
  writeFileSync(join(codeDir, "tools-catalog.json"), JSON.stringify({
    version: "0", tools: [{ tools_name: "curl", description: "d", category: "utility",
      command: { base: "curl", flags: [{ name: "-sS" }, { name: "-I" }], positional: [{ name: "url", required: true }] }, phase: ["utility"] }]
  }))
  const dataDir = mkdtempSync(join(tmpdir(), "omop-exec-data-"))
  mkdirSync(join(dataDir, "engagements", "acme"), { recursive: true })
  writeFileSync(join(dataDir, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(dataDir, "engagements", ".active"), "acme")
  return { codeDir, dataDir }
}

test("P3: split codeDir/dataDir -> in-scope target ALLOW, exec called, audit under dataDir", () => {
  const { codeDir, dataDir } = setupSplit(scope)
  calls = []
  const r = runExec(["curl", "--target", "api.acme.io", "--", "-I"], { codeDir, dataDir, now, exec })
  expect(r.code).toBe(0)
  expect(calls.length).toBe(1)
  expect(calls[0]).toContain("api.acme.io")
  const audit = readFileSync(join(dataDir, "engagements", "acme", "audit.log"), "utf8")
  expect(audit).toMatch(/"decision":"ALLOW"/)
})

test("P3: split codeDir/dataDir -> out-of-scope target DENY exit 2, no exec", () => {
  const { codeDir, dataDir } = setupSplit(scope)
  calls = []
  const r = runExec(["curl", "--target", "evil.com", "--"], { codeDir, dataDir, now, exec })
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
  const audit = readFileSync(join(dataDir, "engagements", "acme", "audit.log"), "utf8")
  expect(audit).toMatch(/"decision":"DENY"/)
})
