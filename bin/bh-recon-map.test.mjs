// bin/bh-recon-map.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, copyFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runReconMap } from "./bh-recon-map.mjs"

const fixturesDir = join(import.meta.dir, "..", "test", "fixtures", "recon")
const now = () => "2026-08-24T00:00:00.000Z"

let root, reconDir

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-recon-map-"))
  reconDir = join(root, "engagements", "acme", "output", "recon")
  mkdirSync(reconDir, { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
})

function seedAllInputs() {
  copyFileSync(join(fixturesDir, "subfinder.jsonl"), join(reconDir, "subfinder.jsonl"))
  copyFileSync(join(fixturesDir, "httpx.jsonl"), join(reconDir, "httpx.jsonl"))
  copyFileSync(join(fixturesDir, "sample.gnmap"), join(reconDir, "host1.gnmap"))
}

test("writes recon-map.json merging the three real input files", () => {
  seedAllInputs()

  const r = runReconMap({ dataDir: root, now })

  expect(r.code).toBe(0)
  const outPath = join(reconDir, "recon-map.json")
  expect(existsSync(outPath)).toBe(true)
  const map = JSON.parse(readFileSync(outPath, "utf8"))
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

test("concatenates multiple *.gnmap files", () => {
  copyFileSync(join(fixturesDir, "subfinder.jsonl"), join(reconDir, "subfinder.jsonl"))
  copyFileSync(join(fixturesDir, "httpx.jsonl"), join(reconDir, "httpx.jsonl"))
  writeFileSync(join(reconDir, "a.gnmap"), 'Host: 1.1.1.1 (a.acme.io)\tPorts: 22/open/tcp//ssh///\tIgnored State: closed (999)\n')
  writeFileSync(join(reconDir, "b.gnmap"), 'Host: 2.2.2.2 (b.acme.io)\tPorts: 80/open/tcp//http///\tIgnored State: closed (999)\n')

  const r = runReconMap({ dataDir: root, now })

  expect(r.code).toBe(0)
  const map = JSON.parse(readFileSync(join(reconDir, "recon-map.json"), "utf8"))
  expect(map.hosts).toEqual([
    { host: "1.1.1.1", ports: [{ port: 22, proto: "tcp", state: "open", service: "ssh" }] },
    { host: "2.2.2.2", ports: [{ port: 80, proto: "tcp", state: "open", service: "http" }] },
  ])
})

test("missing input files are treated as empty, not a crash", () => {
  // No subfinder.jsonl, no httpx.jsonl, no *.gnmap at all in reconDir.
  const r = runReconMap({ dataDir: root, now })

  expect(r.code).toBe(0)
  const map = JSON.parse(readFileSync(join(reconDir, "recon-map.json"), "utf8"))
  expect(map).toEqual({
    generated_at: "2026-08-24T00:00:00.000Z",
    subdomains: [],
    http_services: [],
    hosts: [],
  })
})

test("no active engagement -> fail-closed, no output written", () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-recon-map-bare-"))
  const r = runReconMap({ dataDir: bareRoot, now })
  expect(r.code).toBe(3)
})
