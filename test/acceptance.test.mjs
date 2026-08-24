// test/acceptance.test.mjs
//
// End-to-end acceptance suite for Fase 0 (spec §5, T1-T12). Exercises the
// real safety pipeline (runExec + classifyCommand) with an injected exec so
// no real network calls or docker containers are needed. This file is the
// "Fase 0 done" gate: every T assertion below MUST land on the safe outcome
// (ALLOW where the spec says allow, DENY/exit-2 or fail-closed/exit-3 where
// the spec says deny).
//
// T10 (/engagement + /mode + container lifecycle) and T12 (catalog schema
// validation) are exercised by the Task 12 (bin/omop-engagement.test.mjs),
// Task 6 (src/catalog/catalog-loader.test.mjs) unit suites, and the Task 13
// docker smoke (docker/bridge-smoke.test.mjs, self-skips without a running
// container) rather than here, since they are not reachable purely through
// runExec/classifyCommand. See task-15-report.md for the full mapping.
import { test, expect, beforeEach, afterEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runExec } from "../bin/omop-exec.mjs"
import { classifyCommand } from "../src/guard/guard.mjs"

let root, calls
const now = () => "2026-08-24T00:00:00Z"
const exec = (arr) => { calls.push(arr); return 0 }
const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope: { domains: ["api.acme.io", "*.acme.com"], cidrs: ["203.0.113.0/24"] }
out_of_scope: { domains: ["blog.acme.com"], cidrs: [] }
safety_constraints: { block_destructive: true, block_dos: true }
`
function catalog() {
  // Must declare the flags used by extraArgs below (e.g. "-I") — runExec
  // now rejects any extraArgs token that isn't a declared flag for the
  // tool (closes the target-smuggling hole where a bare URL/host slipped
  // through extraArgs unchecked).
  return JSON.stringify({ version: "0", tools: [{ tools_name: "curl", description: "d",
    category: "utility", command: { base: "curl", flags: [{ name: "-sS" }, { name: "-I" }], positional: [{ name: "url", required: true }] }, phase: ["utility"] }] })
}
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "omop-acc-"))
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(root, "engagements", ".active"), "acme")
  writeFileSync(join(root, "tools-catalog.json"), catalog())
  calls = []
})
afterEach(() => {
  rmSync(root, { recursive: true, force: true })
})
const run = (args) => runExec(args, { rootDir: root, now, exec })

test("T1 in-scope ALLOW + audit", () => {
  expect(run(["curl", "--target", "api.acme.io", "--", "-I"]).code).toBe(0)
  expect(calls.length).toBe(1)
  const audit = readFileSync(join(root, "engagements", "acme", "audit.log"), "utf8")
  expect(audit).toMatch(/"decision":"ALLOW"/)
})

test("T2 out-of-scope DENY (deny-by-default)", () => {
  const r = run(["curl", "--target", "evil.com", "--"])
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
  // Fail loudly if a future refactor changes the reason path: this must
  // stay the deny-by-default fallthrough, not some other DENY reason.
  expect(r.message).toMatch(/deny-by-default/)
})

test("T3 out_of_scope wins over a broader in_scope wildcard -> DENY", () => {
  // blog.acme.com matches out_of_scope exactly AND would also match the
  // in_scope "*.acme.com" wildcard. out_of_scope must win.
  const r = run(["curl", "--target", "blog.acme.com", "--"])
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
  expect(r.message).toMatch(/out_of_scope/)
})

test("T4 direct curl bypass -> guard DENY", () => {
  const r = classifyCommand("curl https://evil.com")
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/direct network tool 'curl'/)
})

test("T5 docker exec bypass -> guard DENY", () => {
  const r = classifyCommand("docker exec omop-acme curl evil.com")
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/docker exec bypass/)
})

test("T6 no active engagement -> fail-closed exit 3", () => {
  writeFileSync(join(root, "engagements", ".active"), "")
  const r = run(["curl", "--target", "api.acme.io", "--"])
  expect(r.code).toBe(3)
  expect(calls.length).toBe(0)
  // runExec formats this as `fail-closed: ${e.message}` where e.message is
  // NoActiveEngagement's "no active engagement" — assert both so a future
  // refactor that silently drops the fail-closed prefix, or that swaps in
  // an unrelated error, fails loudly here.
  expect(r.message).toMatch(/fail-closed/)
  expect(r.message).toMatch(/no active engagement/)
})

test("T7 broken scope.yaml (missing authorization) -> fail-closed exit 3", () => {
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), "engagement: x\n") // missing authorization
  const r = run(["curl", "--target", "api.acme.io", "--"])
  expect(r.code).toBe(3)
  expect(calls.length).toBe(0)
  // `fail-closed: ${ScopeError.message}` — ScopeError's message is
  // "missing authorization" for this exact broken scope.yaml.
  expect(r.message).toMatch(/fail-closed/)
  expect(r.message).toMatch(/missing authorization/)
})

test("T8 destructive flag -> safety DENY exit 2", () => {
  const r = run(["curl", "--target", "api.acme.io", "--", "--os-shell"])
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
  expect(r.message).toMatch(/destructive/)
})

test("T9 scope_enforcement: none lets any target through (no scope check bypassed elsewhere)", () => {
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope.replace("strict", "none"))
  const r = run(["curl", "--target", "anything.example", "--", "-I"])
  expect(r.code).toBe(0)
  expect(calls.length).toBe(1)
  // Prove the rest of the pipeline (safety check, catalog lookup, audit)
  // still ran normally — "none" must bypass only the scope check, not
  // auditing or any other safety gate.
  const audit = readFileSync(join(root, "engagements", "acme", "audit.log"), "utf8")
  const line = JSON.parse(audit.trim().split("\n")[0])
  expect(line.decision).toBe("ALLOW")
  expect(line.target).toBe("anything.example")
})

test("T11 audit line carries all required fields", () => {
  run(["curl", "--target", "api.acme.io", "--"])
  const line = JSON.parse(readFileSync(join(root, "engagements", "acme", "audit.log"), "utf8").trim().split("\n")[0])
  for (const k of ["ts", "target", "tool", "decision", "reason", "authorization"]) {
    expect(Object.hasOwn(line, k)).toBe(true)
  }
  expect(line.authorization).toBe("H1 #1")
  expect(line.decision).toBe("ALLOW")
})

test("T11b audit line is written even on DENY (deny path is auditable too)", () => {
  run(["curl", "--target", "evil.com", "--"])
  const line = JSON.parse(readFileSync(join(root, "engagements", "acme", "audit.log"), "utf8").trim().split("\n")[0])
  expect(line.decision).toBe("DENY")
  for (const k of ["ts", "target", "tool", "decision", "reason", "authorization"]) {
    expect(Object.hasOwn(line, k)).toBe(true)
  }
})
