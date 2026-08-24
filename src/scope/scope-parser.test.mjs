// src/scope/scope-parser.test.mjs
import { test, expect } from "bun:test"
import { parseScope, ScopeError } from "./scope-parser.mjs"

const valid = `
engagement: acme
authorization: "HackerOne #1"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["*.acme.com"]
  cidrs: ["203.0.113.0/24"]
out_of_scope:
  domains: ["blog.acme.com"]
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
`

test("parses a valid scope.yaml", () => {
  const c = parseScope(valid)
  expect(c.engagement).toBe("acme")
  expect(c.scope_enforcement).toBe("strict")
  expect(c.in_scope.domains).toContain("*.acme.com")
  expect(c.safety_constraints.block_destructive).toBe(true)
})

test("rejects missing authorization", () => {
  expect(() => parseScope(`engagement: x\nmode: auto\nscope_enforcement: strict`))
    .toThrow(ScopeError)
})

test("rejects TLD-level wildcard", () => {
  const bad = `engagement: x\nauthorization: "y"\nmode: auto\nscope_enforcement: strict\nin_scope:\n  domains: ["*.com"]`
  expect(() => parseScope(bad)).toThrow(/wildcard/i)
})

test("rejects unknown scope_enforcement value", () => {
  const bad = `engagement: x\nauthorization: "y"\nmode: auto\nscope_enforcement: loose`
  expect(() => parseScope(bad)).toThrow(ScopeError)
})
