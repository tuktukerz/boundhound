// src/report/report.test.mjs
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { buildReport, remediationFor } from "./report.mjs"

const fixturesDir = join(import.meta.dir, "..", "..", "test", "fixtures", "report")
const findings = JSON.parse(readFileSync(join(fixturesDir, "findings.json"), "utf8"))
const meta = JSON.parse(readFileSync(join(fixturesDir, "meta.json"), "utf8"))

const now = () => "2026-08-25T00:00:00.000Z"

// --- R1: structure -----------------------------------------------------

test("R1: title + engagement + metadata present", () => {
  const report = buildReport({ findings, meta }, { now })
  expect(report).toContain("# Penetration Test Report — acme")
  expect(report).toContain("2026-08-25T00:00:00.000Z")
  expect(report).toContain("HackerOne #1")
  expect(report).toContain("bug-bounty")
  expect(report).toContain("strict")
})

test("R1: executive summary has a severity-count table + verified count", () => {
  const report = buildReport({ findings, meta }, { now })
  expect(report).toContain("## Executive Summary")
  // 1 high, 1 medium, 3 info, 0 critical, 0 low (fixture shape)
  expect(report).toContain("| Critical | 0 |")
  expect(report).toContain("| High | 1 |")
  expect(report).toContain("| Medium | 1 |")
  expect(report).toContain("| Low | 0 |")
  expect(report).toContain("| Info | 3 |")
  // 1 finding (the sqli) is verified
  expect(report).toMatch(/verified/i)
  expect(report).toContain("1 of 5")
})

test("R1: a finding heading appears per present severity, in critical->high->medium->low->info order", () => {
  const report = buildReport({ findings, meta }, { now })
  const headingSeverities = [...report.matchAll(/^### \[(\w+)\]/gm)].map((m) => m[1])
  expect(headingSeverities).toEqual(["HIGH", "MEDIUM", "INFO", "INFO", "INFO"])
  // no critical/low present in the fixture -> never emitted
  expect(headingSeverities).not.toContain("CRITICAL")
  expect(headingSeverities).not.toContain("LOW")
})

test("R1: each finding's target and its remediation text appear", () => {
  const report = buildReport({ findings, meta }, { now })
  expect(report).toContain("acme.io")
  expect(report).toContain("http://acme.io")
  expect(report).toContain("api.acme.io")

  expect(report).toContain(remediationFor("sqli"))
  expect(report).toContain(remediationFor("nuclei"))
  expect(report).toContain(remediationFor("open-port"))
  expect(report).toContain(remediationFor("http-service"))
  expect(report).toContain(remediationFor("subdomain"))
})

test("R1: methodology section present and describes the enforced bh-exec choke point", () => {
  const report = buildReport({ findings, meta }, { now })
  expect(report).toContain("## Methodology")
  expect(report).toMatch(/recon/i)
  expect(report).toMatch(/enum/i)
  expect(report).toMatch(/exploit/i)
  expect(report).toMatch(/verif/i)
  expect(report).toContain("bh-exec")
})

test("R1: scope section renders in_scope/out_of_scope domains + cidrs", () => {
  const report = buildReport({ findings, meta }, { now })
  expect(report).toContain("## Scope")
  expect(report).toContain("*.acme.com")
  expect(report).toContain("203.0.113.0/24")
  expect(report).toContain("blog.acme.com")
})

test("R1: appendix renders audit summary when provided", () => {
  const report = buildReport({ findings, meta, auditSummary: { allow: 12, deny: 3, total: 15 } }, { now })
  expect(report).toContain("## Appendix")
  expect(report).toContain("12")
  expect(report).toContain("3")
  expect(report).toContain("15")
  expect(report).toMatch(/ALLOW/)
  expect(report).toMatch(/DENY/)
  expect(report).toContain("output/")
})

test("R1: appendix omits audit line but keeps the output/ note when auditSummary is absent", () => {
  const report = buildReport({ findings, meta }, { now })
  expect(report).toContain("## Appendix")
  expect(report).toContain("output/")
})

// --- R2: determinism + robustness ---------------------------------------

test("R2: same input + now -> byte-identical output", () => {
  const a = buildReport({ findings, meta }, { now })
  const b = buildReport({ findings, meta }, { now })
  expect(a).toBe(b)
})

test("R2: empty findings -> a valid 'No findings recorded.' report, no throw", () => {
  const report = buildReport({ findings: [], meta }, { now })
  expect(report).toContain("No findings recorded.")
  expect(report).toContain("| Critical | 0 |")
  expect(report).toContain("| Info | 0 |")
  expect(report).not.toMatch(/^### \[/m)
})

test("R2: missing findings key entirely -> treated as empty, no throw", () => {
  const report = buildReport({ meta }, { now })
  expect(report).toContain("No findings recorded.")
})

test("R2: garbage findings (not an array) -> treated as empty, no throw", () => {
  expect(() => buildReport({ findings: "not-an-array", meta }, { now })).not.toThrow()
  const report = buildReport({ findings: "not-an-array", meta }, { now })
  expect(report).toContain("No findings recorded.")
})

test("R2: garbage findings elements (null/number/missing fields) -> no throw, safely rendered", () => {
  const garbage = [null, 42, "oops", { type: "nuclei" }, { severity: "not-a-real-severity", type: "content", target: "x.acme.io" }]
  expect(() => buildReport({ findings: garbage, meta }, { now })).not.toThrow()
  const report = buildReport({ findings: garbage, meta }, { now })
  expect(report).toContain("x.acme.io")
})

test("R2: meta with missing fields -> placeholders, no throw", () => {
  const report = buildReport({ findings: [], meta: {} }, { now })
  expect(report).not.toThrow
  expect(report).toContain("(unspecified)")
})

test("R2: missing meta entirely / garbage meta -> no throw", () => {
  expect(() => buildReport({ findings: [] }, { now })).not.toThrow()
  expect(() => buildReport({ findings: [], meta: null }, { now })).not.toThrow()
  expect(() => buildReport({ findings: [], meta: "garbage" }, { now })).not.toThrow()
  expect(() => buildReport(undefined, { now })).not.toThrow()
  expect(() => buildReport()).not.toThrow()
})

test("R2: missing `now` option -> still returns a string, no throw", () => {
  expect(() => buildReport({ findings, meta })).not.toThrow()
  const report = buildReport({ findings, meta })
  expect(typeof report).toBe("string")
  expect(report).toContain("# Penetration Test Report — acme")
})

test("R2: null (not just undefined) arguments -> no throw", () => {
  expect(() => buildReport({ findings, meta }, null)).not.toThrow()
  expect(() => buildReport(null, { now })).not.toThrow()
  expect(() => buildReport(null, null)).not.toThrow()
  expect(() => buildReport("garbage", "garbage")).not.toThrow()
  expect(typeof buildReport(null, null)).toBe("string")
})

// --- R3: remediationFor --------------------------------------------------

test("R3: remediationFor maps each known type to its guidance", () => {
  expect(remediationFor("sqli")).toMatch(/parameteri[sz]ed/i)
  expect(remediationFor("nuclei")).toMatch(/patch|mitigat/i)
  expect(remediationFor("open-port")).toMatch(/firewall/i)
  expect(remediationFor("http-service")).toEqual(expect.any(String))
  expect(remediationFor("content")).toEqual(expect.any(String))
  expect(remediationFor("subdomain")).toEqual(expect.any(String))

  expect(remediationFor("http-service").length).toBeGreaterThan(0)
  expect(remediationFor("content").length).toBeGreaterThan(0)
  expect(remediationFor("subdomain").length).toBeGreaterThan(0)
})

test("R3: remediationFor falls back to a generic string for unknown/garbage types, never throws", () => {
  const generic = remediationFor("something-totally-unknown")
  expect(generic).toMatch(/investigate|remediate/i)
  expect(remediationFor(undefined)).toBe(generic)
  expect(remediationFor(null)).toBe(generic)
  expect(remediationFor(42)).toBe(generic)
  expect(remediationFor({})).toBe(generic)
})
