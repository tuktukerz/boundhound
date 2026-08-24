// src/recon/recon-map.test.mjs
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parseSubfinderJsonl, parseHttpxJsonl, parseNmapGrepable, buildReconMap } from "./recon-map.mjs"

const fixturesDir = join(import.meta.dir, "..", "..", "test", "fixtures", "recon")
const subfinderJsonl = readFileSync(join(fixturesDir, "subfinder.jsonl"), "utf8")
const httpxJsonl = readFileSync(join(fixturesDir, "httpx.jsonl"), "utf8")
const nmapGrepable = readFileSync(join(fixturesDir, "sample.gnmap"), "utf8")

test("parseSubfinderJsonl: collects .host, skips blank/invalid lines", () => {
  expect(parseSubfinderJsonl(subfinderJsonl)).toEqual([
    "api.acme.io",
    "www.acme.io",
    "admin.acme.io",
  ])
})

test("parseSubfinderJsonl: empty text -> empty array", () => {
  expect(parseSubfinderJsonl("")).toEqual([])
})

test("parseHttpxJsonl: parses entries, defaults missing optional fields, skips blank/invalid lines", () => {
  expect(parseHttpxJsonl(httpxJsonl)).toEqual([
    { url: "https://api.acme.io", host: "1.2.3.4", status_code: 200, title: "Acme API", tech: ["nginx", "Ubuntu"] },
    { url: "http://5.6.7.8:8080", host: "5.6.7.8", status_code: 404, title: null, tech: [] },
    { url: "https://www.acme.io", host: "1.2.3.5", status_code: 200, title: "Acme Home", tech: [] },
  ])
})

test("parseHttpxJsonl: empty text -> empty array", () => {
  expect(parseHttpxJsonl("")).toEqual([])
})

test("parseNmapGrepable: parses Host: lines with a Ports: segment, skips comments and Status-only lines", () => {
  expect(parseNmapGrepable(nmapGrepable)).toEqual([
    {
      host: "1.2.3.4",
      ports: [
        { port: 22, proto: "tcp", state: "open", service: "ssh" },
        { port: 80, proto: "tcp", state: "open", service: "http" },
        { port: 443, proto: "tcp", state: "open", service: "https" },
      ],
    },
    {
      host: "5.6.7.8",
      ports: [
        { port: 8080, proto: "tcp", state: "open", service: "http-proxy" },
      ],
    },
  ])
})

test("parseNmapGrepable: empty text -> empty array", () => {
  expect(parseNmapGrepable("")).toEqual([])
})

test("parseNmapGrepable: malformed Host line is skipped, not thrown", () => {
  const text = "Host: totally not a valid line\nHost: 1.2.3.4 (x)\tPorts: 22/open/tcp//ssh///\t\n"
  expect(parseNmapGrepable(text)).toEqual([
    { host: "1.2.3.4", ports: [{ port: 22, proto: "tcp", state: "open", service: "ssh" }] },
  ])
})

test("buildReconMap: merges all three sources with injected now -> deterministic object", () => {
  const now = () => "2026-08-24T00:00:00.000Z"
  const map = buildReconMap({ subfinderJsonl, httpxJsonl, nmapGrepable }, { now })
  expect(map.generated_at).toBe("2026-08-24T00:00:00.000Z")
  expect(map.subdomains).toEqual(["api.acme.io", "www.acme.io", "admin.acme.io"])
  expect(map.http_services).toEqual([
    { url: "https://api.acme.io", host: "1.2.3.4", status_code: 200, title: "Acme API", tech: ["nginx", "Ubuntu"] },
    { url: "http://5.6.7.8:8080", host: "5.6.7.8", status_code: 404, title: null, tech: [] },
    { url: "https://www.acme.io", host: "1.2.3.5", status_code: 200, title: "Acme Home", tech: [] },
  ])
  expect(map.hosts).toEqual([
    { host: "1.2.3.4", ports: [
      { port: 22, proto: "tcp", state: "open", service: "ssh" },
      { port: 80, proto: "tcp", state: "open", service: "http" },
      { port: 443, proto: "tcp", state: "open", service: "https" },
    ] },
    { host: "5.6.7.8", ports: [{ port: 8080, proto: "tcp", state: "open", service: "http-proxy" }] },
  ])
})

test("buildReconMap: missing sources default to empty text -> empty arrays, still has generated_at", () => {
  const now = () => "2026-08-24T00:00:00.000Z"
  const map = buildReconMap({}, { now })
  expect(map).toEqual({
    generated_at: "2026-08-24T00:00:00.000Z",
    subdomains: [],
    http_services: [],
    hosts: [],
  })
})

test("buildReconMap: default now produces an ISO timestamp when none injected", () => {
  const map = buildReconMap({ subfinderJsonl: "", httpxJsonl: "", nmapGrepable: "" })
  expect(map.generated_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
})
