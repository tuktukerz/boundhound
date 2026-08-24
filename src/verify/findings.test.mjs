// src/verify/findings.test.mjs
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { severityFor, buildFindings, applyVerification } from "./findings.mjs"

const fixturesDir = join(import.meta.dir, "..", "..", "test", "fixtures", "verify")
const reconMap = JSON.parse(readFileSync(join(fixturesDir, "recon-map.json"), "utf8"))
const enumMap = JSON.parse(readFileSync(join(fixturesDir, "enum-map.json"), "utf8"))
const exploitMap = JSON.parse(readFileSync(join(fixturesDir, "exploit-map.json"), "utf8"))

const now = () => "2026-08-25T00:00:00.000Z"

// --- severityFor -----------------------------------------------------------

test("severityFor: open-port/http-service/subdomain/content -> info regardless of sourceSeverity", () => {
  expect(severityFor("open-port")).toBe("info")
  expect(severityFor("http-service", "critical")).toBe("info")
  expect(severityFor("subdomain")).toBe("info")
  expect(severityFor("content", "high")).toBe("info")
})

test("severityFor: nuclei -> passes through sourceSeverity", () => {
  expect(severityFor("nuclei", "medium")).toBe("medium")
  expect(severityFor("nuclei", "critical")).toBe("critical")
  expect(severityFor("nuclei", "low")).toBe("low")
})

test("severityFor: nuclei with missing/unknown sourceSeverity -> defaults to info", () => {
  expect(severityFor("nuclei")).toBe("info")
  expect(severityFor("nuclei", undefined)).toBe("info")
  expect(severityFor("nuclei", "not-a-real-severity")).toBe("info")
  expect(severityFor("nuclei", null)).toBe("info")
})

test("severityFor: sqli -> high", () => {
  expect(severityFor("sqli")).toBe("high")
})

test("severityFor: unknown/garbage type -> defaults to info, never throws", () => {
  expect(severityFor("something-else")).toBe("info")
  expect(severityFor(undefined)).toBe("info")
  expect(severityFor(null)).toBe("info")
})

// --- buildFindings: V1 per-source mapping + severity ------------------------

test("buildFindings: recon-map open ports -> normalized info findings with port/proto/service evidence", () => {
  const { findings } = buildFindings({ reconMap }, { now })
  const ports = findings.filter((f) => f.type === "open-port")
  expect(ports).toHaveLength(2)
  const byPort = Object.fromEntries(ports.map((f) => [f.evidence.port, f]))

  expect(byPort[80]).toMatchObject({
    category: "recon",
    type: "open-port",
    target: "acme.io",
    severity: "info",
    confidence: "reported",
    verified: false,
    evidence: { port: 80, proto: "tcp", service: "http" },
  })
  expect(byPort[22]).toMatchObject({
    category: "recon",
    type: "open-port",
    target: "acme.io",
    severity: "info",
    confidence: "reported",
    verified: false,
    evidence: { port: 22, proto: "tcp", service: "ssh" },
  })
  expect(typeof byPort[80].id).toBe("string")
  expect(byPort[80].id.length).toBeGreaterThan(0)
  expect(byPort[80].id).not.toBe(byPort[22].id)
})

test("buildFindings: recon-map http_services + subdomains -> info findings", () => {
  const { findings } = buildFindings({ reconMap }, { now })

  const http = findings.find((f) => f.type === "http-service")
  expect(http).toMatchObject({
    category: "recon",
    type: "http-service",
    target: "http://acme.io",
    severity: "info",
    confidence: "reported",
    verified: false,
    evidence: { status_code: 200, title: "Acme Home", tech: ["nginx"] },
  })

  const subdomains = findings.filter((f) => f.type === "subdomain").map((f) => f.target)
  expect(subdomains.sort()).toEqual(["api.acme.io", "www.acme.io"])
  for (const f of findings.filter((f) => f.type === "subdomain")) {
    expect(f).toMatchObject({ category: "recon", type: "subdomain", severity: "info", confidence: "reported", verified: false })
  }
})

test("buildFindings: enum-map nuclei findings -> severity from source severity", () => {
  const { findings } = buildFindings({ enumMap }, { now })
  const nuclei = findings.filter((f) => f.type === "nuclei")
  expect(nuclei).toHaveLength(2)

  const info = nuclei.find((f) => f.evidence.template_id === "tech-detect-nginx")
  const medium = nuclei.find((f) => f.evidence.template_id === "exposed-panel-admin")
  expect(info.severity).toBe("info")
  expect(medium.severity).toBe("medium")
  expect(medium).toMatchObject({
    category: "enum",
    type: "nuclei",
    target: "http://acme.io",
    confidence: "reported",
    verified: false,
    evidence: { template_id: "exposed-panel-admin", name: "Exposed Admin Panel", matched_at: "http://acme.io/admin" },
  })
})

test("buildFindings: enum-map content (ffuf) -> info findings", () => {
  const { findings } = buildFindings({ enumMap }, { now })
  const content = findings.find((f) => f.type === "content")
  expect(content).toMatchObject({
    category: "enum",
    type: "content",
    target: "http://acme.io/admin",
    severity: "info",
    confidence: "reported",
    verified: false,
    evidence: { path: "admin", status: 200, length: 1234 },
  })
})

test("buildFindings: exploit-map sqli vulnerable:true -> high/confirmed/verified; vulnerable:false -> no finding", () => {
  const { findings } = buildFindings({ exploitMap }, { now })
  const sqli = findings.filter((f) => f.type === "sqli")
  expect(sqli).toHaveLength(1)
  expect(sqli[0]).toMatchObject({
    category: "exploit",
    type: "sqli",
    target: "acme.io",
    severity: "high",
    confidence: "confirmed",
    verified: true,
    evidence: { dbms: "MySQL >= 5.6" },
  })
  // beta.acme.io was vulnerable:false in the fixture -> must produce NO finding
  expect(findings.some((f) => f.target === "beta.acme.io")).toBe(false)
})

test("buildFindings: generated_at comes from injected now", () => {
  const result = buildFindings({ reconMap, enumMap, exploitMap }, { now })
  expect(result.generated_at).toBe("2026-08-25T00:00:00.000Z")
})

test("buildFindings: default now produces an ISO timestamp when none injected", () => {
  const result = buildFindings({})
  expect(result.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
})

// --- V2: determinism + dedup -------------------------------------------------

test("buildFindings: same input twice -> identical id strings (deterministic, no time/random)", () => {
  const a = buildFindings({ reconMap, enumMap, exploitMap }, { now })
  const b = buildFindings({ reconMap, enumMap, exploitMap }, { now })
  expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id))
  expect(a.findings.map((f) => f.id).every((id) => typeof id === "string" && id.length > 0)).toBe(true)
})

test("buildFindings: dedup collapses findings sharing the same id, keeping the highest severity", () => {
  const enumMapDup = {
    ...enumMap,
    findings: [
      ...enumMap.findings,
      // same template_id + host as the existing "medium" finding, reported critical this time
      {
        template_id: "exposed-panel-admin",
        name: "Exposed Admin Panel",
        severity: "critical",
        host: "http://acme.io",
        matched_at: "http://acme.io/admin",
        type: "http",
      },
    ],
  }
  const { findings } = buildFindings({ enumMap: enumMapDup }, { now })
  const matches = findings.filter((f) => f.type === "nuclei" && f.evidence.template_id === "exposed-panel-admin")
  expect(matches).toHaveLength(1)
  expect(matches[0].severity).toBe("critical")
})

test("buildFindings: garbage/empty maps -> empty findings, never throws", () => {
  expect(() => buildFindings()).not.toThrow()
  expect(buildFindings()).toEqual({ generated_at: expect.any(String), findings: [] })

  expect(() => buildFindings({ reconMap: "garbage", enumMap: 42, exploitMap: null }, { now })).not.toThrow()
  expect(buildFindings({ reconMap: "garbage", enumMap: 42, exploitMap: null }, { now })).toEqual({
    generated_at: "2026-08-25T00:00:00.000Z",
    findings: [],
  })

  expect(() =>
    buildFindings(
      {
        reconMap: { hosts: "not-an-array", http_services: [1, 2, 3], subdomains: [null, 5, "ok.acme.io"] },
        enumMap: { findings: [null, "x"], content: [{}] },
        exploitMap: { findings: [{ vulnerable: "yes" }, null] },
      },
      { now }
    )
  ).not.toThrow()
})

// --- V3: applyVerification ----------------------------------------------------

test("applyVerification: reproduced:true matched by id flips verified + confidence", () => {
  const { findings } = buildFindings({ enumMap }, { now })
  const target = findings.find((f) => f.type === "nuclei" && f.evidence.template_id === "exposed-panel-admin")

  const result = applyVerification(findings, [{ id: target.id, reproduced: true }])
  const flipped = result.find((f) => f.id === target.id)
  expect(flipped.verified).toBe(true)
  expect(flipped.confidence).toBe("confirmed")
})

test("applyVerification: reproduced:true matched by type+target+key (no id given)", () => {
  const { findings } = buildFindings({ reconMap }, { now })
  const port80 = findings.find((f) => f.type === "open-port" && f.evidence.port === 80)
  const port22 = findings.find((f) => f.type === "open-port" && f.evidence.port === 22)

  const result = applyVerification(findings, [{ type: "open-port", target: "acme.io", key: 80, reproduced: true }])

  const flipped80 = result.find((f) => f.id === port80.id)
  expect(flipped80.verified).toBe(true)
  expect(flipped80.confidence).toBe("confirmed")

  // port 22 must be untouched -- key disambiguates within the same type+target
  const untouched22 = result.find((f) => f.id === port22.id)
  expect(untouched22.verified).toBe(false)
  expect(untouched22.confidence).toBe("reported")
})

test("applyVerification: reproduced:false leaves verified:false and does NOT drop the finding", () => {
  const { findings } = buildFindings({ enumMap }, { now })
  const target = findings.find((f) => f.type === "nuclei" && f.evidence.template_id === "exposed-panel-admin")

  const result = applyVerification(findings, [{ id: target.id, reproduced: false }])
  expect(result).toHaveLength(findings.length)
  const same = result.find((f) => f.id === target.id)
  expect(same.verified).toBe(false)
  expect(same.confidence).toBe("reported")
})

test("applyVerification: returns a new array and does not mutate input findings", () => {
  const { findings } = buildFindings({ enumMap }, { now })
  const target = findings.find((f) => f.type === "nuclei" && f.evidence.template_id === "exposed-panel-admin")
  const before = JSON.stringify(findings)

  const result = applyVerification(findings, [{ id: target.id, reproduced: true }])

  expect(JSON.stringify(findings)).toBe(before)
  expect(result).not.toBe(findings)
})

test("applyVerification: garbage recheckResults/findings -> no throw, tolerant defaults", () => {
  expect(() => applyVerification(undefined, undefined)).not.toThrow()
  expect(applyVerification(undefined, undefined)).toEqual([])
  expect(() => applyVerification([{ id: "x" }], "not-an-array")).not.toThrow()
  expect(() => applyVerification([null, 42, { id: "x", type: "open-port", target: "h" }], [{ reproduced: true }])).not.toThrow()
  expect(() => applyVerification(null, [{ reproduced: true }])).not.toThrow()
})
