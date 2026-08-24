// bin/bh-findings.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runFindings } from "./bh-findings.mjs"

const now = () => "2026-08-25T00:00:00.000Z"

let root, outputDir

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-findings-"))
  outputDir = join(root, "engagements", "acme", "output")
  mkdirSync(outputDir, { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
})

function writeMap(sub, name, obj) {
  const dir = join(outputDir, sub)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, name), JSON.stringify(obj))
}

const reconMap = {
  generated_at: "x",
  subdomains: [],
  http_services: [{ url: "http://acme.io", host: "acme.io", status_code: 200, title: "Acme Home", tech: ["nginx"] }],
  hosts: [
    {
      host: "acme.io",
      ports: [
        { port: 80, proto: "tcp", state: "open", service: "http" },
        { port: 22, proto: "tcp", state: "open", service: "ssh" },
      ],
    },
  ],
}

const enumMap = {
  generated_at: "x",
  content: [],
  findings: [
    {
      template_id: "exposed-panel-admin",
      name: "Exposed Admin Panel",
      severity: "medium",
      host: "http://acme.io",
      matched_at: "http://acme.io/admin",
      type: "http",
    },
    {
      template_id: "tech-detect-nginx",
      name: "Nginx Detect",
      severity: "info",
      host: "http://acme.io",
      matched_at: "http://acme.io/",
      type: "http",
    },
  ],
  by_severity: { info: 1, low: 0, medium: 1, high: 0, critical: 0 },
}

const exploitMap = {
  generated_at: "x",
  findings: [{ target: "acme.io", vulnerable: true, dbms: "MySQL >= 5.6", injection_points: [], databases: [] }],
}

test("writes findings.json consolidating the three maps; a reproduced nuclei recheck flips only the matching finding to verified", () => {
  writeMap("recon", "recon-map.json", reconMap)
  writeMap("enum", "enum-map.json", enumMap)
  writeMap("exploit", "exploit-map.json", exploitMap)

  const recheckDir = join(outputDir, "verify", "recheck")
  mkdirSync(recheckDir, { recursive: true })
  // Same template_id + host as the "exposed-panel-admin" enum finding ->
  // reproduces it. "tech-detect-nginx" is NOT re-fired here, so it must
  // stay unverified.
  writeFileSync(
    join(recheckDir, "acme.io.jsonl"),
    JSON.stringify({
      "template-id": "exposed-panel-admin",
      info: { name: "Exposed Admin Panel", severity: "medium" },
      type: "http",
      host: "http://acme.io",
      "matched-at": "http://acme.io/admin",
    }) + "\n"
  )

  const r = runFindings({ dataDir: root, now })

  expect(r.code).toBe(0)
  const outPath = join(outputDir, "verify", "findings.json")
  expect(existsSync(outPath)).toBe(true)
  const written = JSON.parse(readFileSync(outPath, "utf8"))
  expect(written.generated_at).toBe("2026-08-25T00:00:00.000Z")

  // 2 open-port + 1 http-service + 2 nuclei + 1 sqli = 6
  expect(written.findings).toHaveLength(6)

  const reproduced = written.findings.find((f) => f.type === "nuclei" && f.evidence.template_id === "exposed-panel-admin")
  expect(reproduced.verified).toBe(true)
  expect(reproduced.confidence).toBe("confirmed")

  const notReproduced = written.findings.find((f) => f.type === "nuclei" && f.evidence.template_id === "tech-detect-nginx")
  expect(notReproduced.verified).toBe(false)
  expect(notReproduced.confidence).toBe("reported")

  // sqli was already confirmed by sqlmap itself, independent of any recheck.
  const sqli = written.findings.find((f) => f.type === "sqli")
  expect(sqli.verified).toBe(true)

  // open-port / http-service findings had no recheck at all -> untouched.
  for (const f of written.findings.filter((f) => f.type === "open-port" || f.type === "http-service")) {
    expect(f.verified).toBe(false)
  }
})

test("a live httpx recheck reproduces the matching http-service finding", () => {
  writeMap("recon", "recon-map.json", reconMap)

  const recheckDir = join(outputDir, "verify", "recheck")
  mkdirSync(recheckDir, { recursive: true })
  writeFileSync(
    join(recheckDir, "probe.httpx.jsonl"),
    JSON.stringify({ url: "http://acme.io", host: "acme.io", status_code: 200, title: "Acme Home", tech: ["nginx"] }) + "\n"
  )

  const r = runFindings({ dataDir: root, now })
  expect(r.code).toBe(0)
  const written = JSON.parse(readFileSync(join(outputDir, "verify", "findings.json"), "utf8"))
  const http = written.findings.find((f) => f.type === "http-service")
  expect(http.verified).toBe(true)
  expect(http.confidence).toBe("confirmed")
})

test("an nmap .gnmap recheck reproduces only the port still reported open", () => {
  writeMap("recon", "recon-map.json", reconMap)

  const recheckDir = join(outputDir, "verify", "recheck")
  mkdirSync(recheckDir, { recursive: true })
  // Only port 80 still shows open on recheck; port 22 is absent entirely.
  writeFileSync(join(recheckDir, "acme.io.gnmap"), "Host: acme.io (acme.io)\tPorts: 80/open/tcp//http///\n")

  const r = runFindings({ dataDir: root, now })
  expect(r.code).toBe(0)
  const written = JSON.parse(readFileSync(join(outputDir, "verify", "findings.json"), "utf8"))
  const port80 = written.findings.find((f) => f.type === "open-port" && f.evidence.port === 80)
  const port22 = written.findings.find((f) => f.type === "open-port" && f.evidence.port === 22)
  expect(port80.verified).toBe(true)
  expect(port22.verified).toBe(false)
})

test("missing maps -> empty findings, no crash", () => {
  const r = runFindings({ dataDir: root, now })
  expect(r.code).toBe(0)
  const outPath = join(outputDir, "verify", "findings.json")
  expect(existsSync(outPath)).toBe(true)
  const written = JSON.parse(readFileSync(outPath, "utf8"))
  expect(written).toEqual({ generated_at: "2026-08-25T00:00:00.000Z", findings: [] })
})

test("missing verify/recheck dir entirely -> no crash, findings still written unverified", () => {
  writeMap("enum", "enum-map.json", enumMap)
  const r = runFindings({ dataDir: root, now })
  expect(r.code).toBe(0)
  const written = JSON.parse(readFileSync(join(outputDir, "verify", "findings.json"), "utf8"))
  expect(written.findings.length).toBeGreaterThan(0)
  expect(written.findings.every((f) => f.verified === false)).toBe(true)
})

test("invalid/corrupt map JSON is treated as missing, not a crash", () => {
  const dir = join(outputDir, "enum")
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, "enum-map.json"), "{not valid json")

  const r = runFindings({ dataDir: root, now })
  expect(r.code).toBe(0)
  const written = JSON.parse(readFileSync(join(outputDir, "verify", "findings.json"), "utf8"))
  expect(written.findings).toEqual([])
})

test("no active engagement -> fail-closed, no output written", () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-findings-bare-"))
  const r = runFindings({ dataDir: bareRoot, now })
  expect(r.code).toBe(3)
  expect(existsSync(join(bareRoot, "engagements"))).toBe(false)
})
