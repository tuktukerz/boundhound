// src/guard/burp-guard.test.mjs
import { test, expect } from "bun:test"
import { isBurpMcpTool, extractBurpTarget, decideBurpMcp } from "./burp-guard.mjs"

// --- isBurpMcpTool ----------------------------------------------------------

test("isBurpMcpTool: true for mcp__burp__* tool names", () => {
  expect(isBurpMcpTool("mcp__burp__send_request")).toBe(true)
})

test("isBurpMcpTool: true for burp anywhere in the mcp__ prefixed name, case-insensitive", () => {
  expect(isBurpMcpTool("mcp__pro_burp__scan")).toBe(true)
  expect(isBurpMcpTool("mcp__BURP__send_request")).toBe(true)
  expect(isBurpMcpTool("mcp__Pro_Burp__scan")).toBe(true)
})

test("isBurpMcpTool: false for non-burp mcp tools", () => {
  expect(isBurpMcpTool("mcp__github__x")).toBe(false)
})

test("isBurpMcpTool: false for non-mcp tools", () => {
  expect(isBurpMcpTool("Bash")).toBe(false)
})

test("isBurpMcpTool: false for burp not prefixed with mcp__", () => {
  expect(isBurpMcpTool("burp_send_request")).toBe(false)
})

test("isBurpMcpTool: false for empty string and non-string inputs", () => {
  expect(isBurpMcpTool("")).toBe(false)
  expect(isBurpMcpTool(null)).toBe(false)
  expect(isBurpMcpTool(undefined)).toBe(false)
  expect(isBurpMcpTool(123)).toBe(false)
  expect(isBurpMcpTool({})).toBe(false)
  expect(isBurpMcpTool(["mcp__burp__x"])).toBe(false)
})

// --- extractBurpTarget -------------------------------------------------------

test("extractBurpTarget: from toolInput.url", () => {
  expect(extractBurpTarget({ url: "http://acme.io/x" })).toBe("http://acme.io/x")
})

test("extractBurpTarget: from toolInput.target", () => {
  expect(extractBurpTarget({ target: "acme.io" })).toBe("acme.io")
})

test("extractBurpTarget: from toolInput.targetUrl", () => {
  expect(extractBurpTarget({ targetUrl: "https://acme.io/y" })).toBe("https://acme.io/y")
})

test("extractBurpTarget: from toolInput.host", () => {
  expect(extractBurpTarget({ host: "acme.io" })).toBe("acme.io")
})

test("extractBurpTarget: from toolInput.host + port", () => {
  expect(extractBurpTarget({ host: "acme.io", port: 8443 })).toBe("acme.io:8443")
})

test("extractBurpTarget: precedence url > target > targetUrl > host", () => {
  expect(extractBurpTarget({ url: "http://a.io", target: "b.io", targetUrl: "http://c.io", host: "d.io" })).toBe(
    "http://a.io",
  )
})

test("extractBurpTarget: from raw request field with request-line absolute URL", () => {
  const request = "GET http://acme.io/path HTTP/1.1\r\nHost: acme.io\r\n\r\n"
  expect(extractBurpTarget({ request })).toBe("http://acme.io/path")
})

test("extractBurpTarget: from raw request field with Host header only", () => {
  const request = "GET /path HTTP/1.1\r\nHost: acme.io\r\n\r\n"
  expect(extractBurpTarget({ request })).toBe("acme.io")
})

test("extractBurpTarget: checks httpRequest and rawRequest fields too", () => {
  expect(extractBurpTarget({ httpRequest: "GET / HTTP/1.1\r\nHost: acme.io\r\n\r\n" })).toBe("acme.io")
  expect(extractBurpTarget({ rawRequest: "GET / HTTP/1.1\r\nHost: acme.io\r\n\r\n" })).toBe("acme.io")
})

test("extractBurpTarget: null when nothing usable is present", () => {
  expect(extractBurpTarget({})).toBe(null)
})

test("extractBurpTarget: null for null/non-object/garbage inputs", () => {
  expect(extractBurpTarget(null)).toBe(null)
  expect(extractBurpTarget(undefined)).toBe(null)
  expect(extractBurpTarget("http://acme.io")).toBe(null)
  expect(extractBurpTarget({ foo: 1 })).toBe(null)
  expect(extractBurpTarget(42)).toBe(null)
})

// --- decideBurpMcp -----------------------------------------------------------

const cfg = {
  in_scope: { domains: ["*.acme.com", "acme.io"], cidrs: [] },
  out_of_scope: { domains: ["blog.acme.com"], cidrs: [] },
}

test("decideBurpMcp: no scopeConfig -> DENY no-active-scope", () => {
  expect(decideBurpMcp({ url: "http://acme.io" }, null)).toEqual({
    decision: "DENY",
    reason: "no-active-scope",
  })
  expect(decideBurpMcp({ url: "http://acme.io" }, undefined)).toEqual({
    decision: "DENY",
    reason: "no-active-scope",
  })
})

test("decideBurpMcp: unresolvable target -> DENY burp-target-unresolved", () => {
  expect(decideBurpMcp({}, cfg)).toEqual({
    decision: "DENY",
    reason: "burp-target-unresolved",
  })
})

test("decideBurpMcp: out-of-scope target -> DENY", () => {
  const r = decideBurpMcp({ url: "http://blog.acme.com/x" }, cfg)
  expect(r.decision).toBe("DENY")
})

test("decideBurpMcp: unlisted target -> DENY deny-by-default", () => {
  const r = decideBurpMcp({ url: "http://evil.com/x" }, cfg)
  expect(r.decision).toBe("DENY")
})

test("decideBurpMcp: in-scope target -> ALLOW", () => {
  const r = decideBurpMcp({ url: "http://acme.io/x" }, cfg)
  expect(r.decision).toBe("ALLOW")
})

test("decideBurpMcp: in-scope wildcard target -> ALLOW", () => {
  const r = decideBurpMcp({ target: "a.acme.com" }, cfg)
  expect(r.decision).toBe("ALLOW")
})

test("decideBurpMcp: never throws on garbage input", () => {
  expect(() => decideBurpMcp(null, cfg)).not.toThrow()
  expect(decideBurpMcp(null, cfg).decision).toBe("DENY")
  expect(() => decideBurpMcp(undefined, undefined)).not.toThrow()
  expect(() => isBurpMcpTool(Symbol("x"))).not.toThrow()
  expect(() => extractBurpTarget(() => {})).not.toThrow()
})
