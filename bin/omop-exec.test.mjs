// bin/omop-exec.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs"
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
  // catalog: copy the repo's for curl
  writeFileSync(join(root, "tools-catalog.json"), JSON.stringify({
    version: "0", tools: [{ tools_name: "curl", description: "d", category: "utility",
      command: { base: "curl", flags: [], positional: [{ name: "url", required: true }] }, phase: ["utility"] }]
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
