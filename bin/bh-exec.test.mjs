// bin/bh-exec.test.mjs
import { test, expect, beforeEach, describe } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runExec } from "./bh-exec.mjs"

let root, calls
const now = () => "2026-08-24T00:00:00Z"
const exec = (arr) => { calls.push(arr); return 0 }

function setup(scope) {
  root = mkdtempSync(join(tmpdir(), "bh-exec-"))
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

// Task 2: extraArgs value-flag walk (nmap-like entry: -sV boolean, -p and
// -oG take_value with tight regex patterns). Same two patterns the real
// catalog will use in a later task — kept here verbatim so they don't drift.
// Scoped in its own describe() so this block's beforeEach (a different
// catalog/tool than the file-level curl setup above) doesn't leak into the
// pre-existing curl tests or the P3 split-dir tests below.
describe("Task 2: extraArgs value-flag walk", () => {
  const P_PATTERN = "^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$"
  const OG_PATTERN = "^-$"

  function setupNmapLike(scope) {
    root = mkdtempSync(join(tmpdir(), "bh-exec-"))
    mkdirSync(join(root, "engagements", "acme"), { recursive: true })
    writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
    writeFileSync(join(root, "engagements", ".active"), "acme")
    writeFileSync(join(root, "tools-catalog.json"), JSON.stringify({
      version: "0",
      tools: [{
        tools_name: "nmap", description: "d", category: "recon",
        command: {
          base: "nmap",
          flags: [
            { name: "-sV" },
            { name: "-p", takes_value: true, value_pattern: P_PATTERN },
            { name: "-oG", takes_value: true, value_pattern: OG_PATTERN },
          ],
          positional: [{ name: "target", required: true }],
        },
        phase: ["recon"],
      }],
    }))
    calls = []
  }

  beforeEach(() => setupNmapLike(scope))

  test("T2a: boolean + value flag with valid value -> ALLOW, value passed through", () => {
    const r = runExec(["nmap", "--target", "api.acme.io", "--", "-sV", "-p", "22,80"], { rootDir: root, now, exec })
    expect(r.code).toBe(0)
    expect(calls.length).toBe(1)
    expect(calls[0]).toEqual(["nmap", "-sV", "-p", "22,80", "api.acme.io"])
  })

  test("T2b: value flag with value failing pattern -> DENY exit 2, no exec", () => {
    const r = runExec(["nmap", "--target", "api.acme.io", "--", "-p", "evil.com"], { rootDir: root, now, exec })
    expect(r.code).toBe(2)
    expect(calls.length).toBe(0)
  })

  test("T2c: value flag with no following token -> DENY exit 2, no exec", () => {
    const r = runExec(["nmap", "--target", "api.acme.io", "--", "-p"], { rootDir: root, now, exec })
    expect(r.code).toBe(2)
    expect(calls.length).toBe(0)
  })

  test("T2d: undeclared token -> DENY exit 2, no exec", () => {
    const r = runExec(["nmap", "--target", "api.acme.io", "--", "--undeclared"], { rootDir: root, now, exec })
    expect(r.code).toBe(2)
    expect(calls.length).toBe(0)
  })

  test("T2e: -oG - -> ALLOW (value matches ^-$)", () => {
    const r = runExec(["nmap", "--target", "api.acme.io", "--", "-oG", "-"], { rootDir: root, now, exec })
    expect(r.code).toBe(0)
    expect(calls.length).toBe(1)
    expect(calls[0]).toEqual(["nmap", "-oG", "-", "api.acme.io"])
  })

  test("T2f regression: curl boolean-only flags still ALLOW", () => {
    root = mkdtempSync(join(tmpdir(), "bh-exec-"))
    mkdirSync(join(root, "engagements", "acme"), { recursive: true })
    writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
    writeFileSync(join(root, "engagements", ".active"), "acme")
    writeFileSync(join(root, "tools-catalog.json"), JSON.stringify({
      version: "0", tools: [{ tools_name: "curl", description: "d", category: "utility",
        command: { base: "curl", flags: [{ name: "-sS" }, { name: "-I" }], positional: [{ name: "url", required: true }] }, phase: ["utility"] }]
    }))
    calls = []
    const r = runExec(["curl", "--target", "api.acme.io", "--", "-sS", "-I"], { rootDir: root, now, exec })
    expect(r.code).toBe(0)
    expect(calls.length).toBe(1)
    expect(calls[0]).toEqual(["curl", "-sS", "-I", "api.acme.io"])
  })

  test("T2f regression: bare URL smuggled in extraArgs still DENYs (nmap-like catalog)", () => {
    const r = runExec(["nmap", "--target", "api.acme.io", "--", "https://evil.com"], { rootDir: root, now, exec })
    expect(r.code).toBe(2)
    expect(calls.length).toBe(0)
  })
})

// P3: split codeDir/dataDir must behave identically to the single-rootDir
// case above — same ALLOW/DENY decisions, audit still lands under dataDir.
function setupSplit(scope) {
  const codeDir = mkdtempSync(join(tmpdir(), "bh-exec-code-"))
  writeFileSync(join(codeDir, "tools-catalog.json"), JSON.stringify({
    version: "0", tools: [{ tools_name: "curl", description: "d", category: "utility",
      command: { base: "curl", flags: [{ name: "-sS" }, { name: "-I" }], positional: [{ name: "url", required: true }] }, phase: ["utility"] }]
  }))
  const dataDir = mkdtempSync(join(tmpdir(), "bh-exec-data-"))
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
