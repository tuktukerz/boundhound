// bin/bh-enum-map.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, copyFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runEnumMap } from "./bh-enum-map.mjs"

const fixturesDir = join(import.meta.dir, "..", "test", "fixtures", "enum")
const now = () => "2026-08-24T00:00:00.000Z"

let root, enumDir

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-enum-map-"))
  enumDir = join(root, "engagements", "acme", "output", "enum")
  mkdirSync(enumDir, { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
})

function seedAllInputs() {
  copyFileSync(join(fixturesDir, "ffuf.json"), join(enumDir, "ffuf.json"))
  copyFileSync(join(fixturesDir, "nuclei.jsonl"), join(enumDir, "nuclei.jsonl"))
}

test("writes enum-map.json merging the real ffuf + nuclei input files", () => {
  seedAllInputs()

  const r = runEnumMap({ dataDir: root, now })

  expect(r.code).toBe(0)
  const outPath = join(enumDir, "enum-map.json")
  expect(existsSync(outPath)).toBe(true)
  const map = JSON.parse(readFileSync(outPath, "utf8"))
  expect(map.generated_at).toBe("2026-08-24T00:00:00.000Z")
  expect(map.content).toEqual([
    { url: "http://acme.io/admin", path: "admin", status: 200, length: 1234, words: 42, host: "acme.io" },
    { url: "http://acme.io/backup", path: "backup", status: 301, length: 0, words: 1, host: "acme.io" },
  ])
  expect(map.findings).toEqual([
    {
      template_id: "tech-detect-nginx",
      name: "Nginx Detect",
      severity: "info",
      host: "http://acme.io",
      matched_at: "http://acme.io/",
      type: "http",
    },
    {
      template_id: "exposed-panel-admin",
      name: "Exposed Admin Panel",
      severity: "high",
      host: "http://acme.io",
      matched_at: "http://acme.io/admin",
      type: "http",
    },
  ])
  expect(map.by_severity).toEqual({ info: 1, low: 0, medium: 0, high: 1, critical: 0 })
})

test("merges multiple ffuf*.json files (parsed separately) and concatenates multiple nuclei*.jsonl files", () => {
  writeFileSync(
    join(enumDir, "ffuf-host1.json"),
    JSON.stringify({
      results: [
        { input: { FUZZ: "login" }, status: 200, length: 10, words: 2, url: "http://host1/login", host: "host1" },
      ],
    })
  )
  writeFileSync(
    join(enumDir, "ffuf-host2.json"),
    JSON.stringify({
      results: [
        { input: { FUZZ: "config" }, status: 200, length: 20, words: 3, url: "http://host2/config", host: "host2" },
      ],
    })
  )
  writeFileSync(
    join(enumDir, "nuclei-host1.jsonl"),
    JSON.stringify({
      "template-id": "exposed-config",
      info: { name: "Exposed Config", severity: "medium" },
      type: "http",
      host: "http://host1",
      "matched-at": "http://host1/login",
    }) + "\n"
  )
  writeFileSync(
    join(enumDir, "nuclei-host2.jsonl"),
    JSON.stringify({
      "template-id": "critical-rce",
      info: { name: "Critical RCE", severity: "critical" },
      type: "http",
      host: "http://host2",
      "matched-at": "http://host2/config",
    }) + "\n"
  )

  const r = runEnumMap({ dataDir: root, now })

  expect(r.code).toBe(0)
  const map = JSON.parse(readFileSync(join(enumDir, "enum-map.json"), "utf8"))
  expect(map.content).toEqual([
    { url: "http://host1/login", path: "login", status: 200, length: 10, words: 2, host: "host1" },
    { url: "http://host2/config", path: "config", status: 200, length: 20, words: 3, host: "host2" },
  ])
  expect(map.findings).toEqual([
    {
      template_id: "exposed-config",
      name: "Exposed Config",
      severity: "medium",
      host: "http://host1",
      matched_at: "http://host1/login",
      type: "http",
    },
    {
      template_id: "critical-rce",
      name: "Critical RCE",
      severity: "critical",
      host: "http://host2",
      matched_at: "http://host2/config",
      type: "http",
    },
  ])
  expect(map.by_severity).toEqual({ info: 0, low: 0, medium: 1, high: 0, critical: 1 })
})

test("missing input files are treated as empty, not a crash", () => {
  // No ffuf*.json, no nuclei*.jsonl at all in enumDir.
  const r = runEnumMap({ dataDir: root, now })

  expect(r.code).toBe(0)
  const map = JSON.parse(readFileSync(join(enumDir, "enum-map.json"), "utf8"))
  expect(map).toEqual({
    generated_at: "2026-08-24T00:00:00.000Z",
    content: [],
    findings: [],
    by_severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
  })
})

test("missing enum output dir entirely is treated as empty, not a crash", () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-enum-map-nodir-"))
  mkdirSync(join(bareRoot, "engagements"), { recursive: true })
  writeFileSync(join(bareRoot, "engagements", ".active"), "acme")

  const r = runEnumMap({ dataDir: bareRoot, now })

  expect(r.code).toBe(0)
  const map = JSON.parse(readFileSync(join(bareRoot, "engagements", "acme", "output", "enum", "enum-map.json"), "utf8"))
  expect(map.content).toEqual([])
  expect(map.findings).toEqual([])
})

test("no active engagement -> fail-closed, no output written", () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-enum-map-bare-"))
  const r = runEnumMap({ dataDir: bareRoot, now })
  expect(r.code).toBe(3)
})
