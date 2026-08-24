// src/scope/scope-matcher.test.mjs
import { test, expect } from "bun:test"
import { matchTarget, normalizeTarget } from "./scope-matcher.mjs"

const cfg = {
  in_scope: { domains: ["*.acme.com", "api.acme.io"], cidrs: ["203.0.113.0/24"] },
  out_of_scope: { domains: ["blog.acme.com"], cidrs: ["203.0.113.5/32"] },
}

test("normalizes url/port to hostname", () => {
  expect(normalizeTarget("https://api.acme.io:443/x?y=1")).toBe("api.acme.io")
  expect(normalizeTarget("api.acme.io")).toBe("api.acme.io")
})

test("in-scope wildcard domain -> ALLOW", () => {
  expect(matchTarget("a.acme.com", cfg).decision).toBe("ALLOW")
})

test("in-scope exact domain -> ALLOW", () => {
  expect(matchTarget("api.acme.io", cfg).decision).toBe("ALLOW")
})

test("in-scope CIDR -> ALLOW", () => {
  expect(matchTarget("203.0.113.9", cfg).decision).toBe("ALLOW")
})

test("out_of_scope wins over in_scope", () => {
  const r = matchTarget("blog.acme.com", cfg)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/out_of_scope/)
})

test("out_of_scope CIDR /32 -> DENY", () => {
  expect(matchTarget("203.0.113.5", cfg).decision).toBe("DENY")
})

test("unlisted target -> DENY deny-by-default", () => {
  const r = matchTarget("evil.com", cfg)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/deny-by-default/)
})
