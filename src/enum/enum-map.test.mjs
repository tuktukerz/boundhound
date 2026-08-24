// src/enum/enum-map.test.mjs
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parseFfufJson, parseNucleiJsonl, buildEnumMap } from "./enum-map.mjs"

const fixturesDir = join(import.meta.dir, "..", "..", "test", "fixtures", "enum")
const ffufJson = readFileSync(join(fixturesDir, "ffuf.json"), "utf8")
const nucleiJsonl = readFileSync(join(fixturesDir, "nuclei.jsonl"), "utf8")

test("parseFfufJson: collects url/path/status/length/words/host from results[]", () => {
  expect(parseFfufJson(ffufJson)).toEqual([
    { url: "http://acme.io/admin", path: "admin", status: 200, length: 1234, words: 42, host: "acme.io" },
    { url: "http://acme.io/backup", path: "backup", status: 301, length: 0, words: 1, host: "acme.io" },
  ])
})

test("parseFfufJson: empty text -> empty array", () => {
  expect(parseFfufJson("")).toEqual([])
})

test("parseFfufJson: invalid JSON -> empty array, not thrown", () => {
  expect(parseFfufJson("not valid json at all")).toEqual([])
})

test("parseFfufJson: missing results key -> empty array", () => {
  expect(parseFfufJson("{}")).toEqual([])
})

test("parseFfufJson: empty results array -> empty array", () => {
  expect(parseFfufJson(JSON.stringify({ results: [] }))).toEqual([])
})

// Fix-wave FIX 2: ffuf's real "-o /dev/stdout -of json -s" invocation
// (see pentest-enum/SKILL.md Step 1) does not put PURE JSON on stdout --
// verified by hand against bh:base -- ffuf also writes one bare per-match
// progress line to stdout ahead of the JSON blob, with or without -s, when
// its -o target happens to be stdout itself. A direct JSON.parse on that
// raw text throws; parseFfufJson must recover the real JSON object instead
// of silently returning [] (which would be the exact "100% of ffuf
// findings lost" bug this fix wave closes, just moved one layer down).

test("parseFfufJson: tolerates ffuf's own leading match-progress line before the JSON blob (real -o /dev/stdout shape)", () => {
  const noisy = "index.html\n" + ffufJson
  expect(parseFfufJson(noisy)).toEqual(parseFfufJson(ffufJson))
})

test("parseFfufJson: tolerates multiple leading match-progress lines (multiple matches found)", () => {
  const noisy = "index.html\nadmin\nbackup\n" + ffufJson
  expect(parseFfufJson(noisy)).toEqual(parseFfufJson(ffufJson))
})

test("parseFfufJson: leading noise with no JSON at all still -> empty array, not thrown", () => {
  expect(parseFfufJson("index.html\nadmin\n")).toEqual([])
})

test("parseNucleiJsonl: collects template_id/name/severity/host/matched_at/type, skips blank/invalid lines", () => {
  expect(parseNucleiJsonl(nucleiJsonl)).toEqual([
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
})

test("parseNucleiJsonl: empty text -> empty array", () => {
  expect(parseNucleiJsonl("")).toEqual([])
})

test("buildEnumMap: merges ffuf + nuclei with injected now -> deterministic object incl. by_severity counts", () => {
  const now = () => "2026-08-24T00:00:00.000Z"
  const map = buildEnumMap({ ffufJson, nucleiJsonl }, { now })
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

test("buildEnumMap: missing sources default to empty text -> empty arrays, zeroed by_severity, still has generated_at", () => {
  const now = () => "2026-08-24T00:00:00.000Z"
  const map = buildEnumMap({}, { now })
  expect(map).toEqual({
    generated_at: "2026-08-24T00:00:00.000Z",
    content: [],
    findings: [],
    by_severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
  })
})

test("buildEnumMap: default now produces an ISO timestamp when none injected", () => {
  const map = buildEnumMap({ ffufJson: "", nucleiJsonl: "" })
  expect(map.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
})
