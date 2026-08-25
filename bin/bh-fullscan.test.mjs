// bin/bh-fullscan.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runFullscan } from "./bh-fullscan.mjs"

let root, engagementDir, outputDir

const VALID_SCOPE = `
engagement: acme
authorization: "acme SOW ref #123"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains:
    - acme.io
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: ""
`

// Missing "authorization:" -> parseScope's ScopeError("missing authorization"),
// same fixture bh-report.test.mjs uses for the broken-scope fail-closed case.
const BROKEN_SCOPE = `
engagement: acme
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: []
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
`

// One http_service carrying a query param (acme.io/search?q=x) so every
// stage in the fixed chain plans exactly one step: subfinder/httpx/nmap off
// the "acme.io" root + reconMap.hosts, nuclei/ffuf off the http_service url,
// sqlmap off that same url's "q" param.
const RECON_MAP = {
  generated_at: "2026-08-25T00:00:00.000Z",
  subdomains: [],
  http_services: [
    { url: "http://acme.io/search?q=x", host: "acme.io", status_code: 200, title: "t", tech: [] },
  ],
  hosts: [
    { host: "acme.io", ports: [{ port: 80, proto: "tcp", state: "open", service: "http" }] },
  ],
}

function writeScope(text) {
  writeFileSync(join(engagementDir, "scope.yaml"), text)
}

function seedReconMap() {
  const reconDir = join(outputDir, "recon")
  mkdirSync(reconDir, { recursive: true })
  writeFileSync(join(reconDir, "recon-map.json"), JSON.stringify(RECON_MAP))
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-fullscan-"))
  engagementDir = join(root, "engagements", "acme")
  outputDir = join(engagementDir, "output")
  mkdirSync(outputDir, { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "acme")
})

// A canned-success fake `spawn` (spawnSync's shape): records every
// (cmd, args) call and always reports exit 0 with fixed stdout, so no real
// process (docker, node subprocess) is ever started.
function fakeSpawn(calls, { stdout = "canned-output\n" } = {}) {
  return (cmd, args, opts) => {
    calls.push({ cmd, args, opts })
    return { status: 0, stdout, stderr: "" }
  }
}

function execCalls(calls) {
  return calls.filter((c) => c.args[0].endsWith("bh-exec.mjs"))
}
function synthCalls(calls) {
  return calls.filter((c) => !c.args[0].endsWith("bh-exec.mjs"))
}

// --- fail-closed --------------------------------------------------------

test("no active engagement -> code 3, zero spawns", async () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-fullscan-bare-"))
  const calls = []
  const r = await runFullscan({ dataDir: bareRoot, spawn: fakeSpawn(calls) })
  expect(r.code).toBe(3)
  expect(calls.length).toBe(0)
})

test("broken scope.yaml (missing authorization) -> code 3, zero spawns", async () => {
  writeScope(BROKEN_SCOPE)
  seedReconMap()
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls) })
  expect(r.code).toBe(3)
  expect(calls.length).toBe(0)
})

test("missing scope.yaml entirely -> code 3, zero spawns", async () => {
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls) })
  expect(r.code).toBe(3)
  expect(calls.length).toBe(0)
})

// --- real wiring ----------------------------------------------------------

test("valid engagement -> constructs correct bh-exec commands per stage, in fixed order", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls) })

  expect(r.code).toBe(0)

  const exec = execCalls(calls)
  // one step per stage (subfinder, httpx, nmap, nuclei, ffuf, sqlmap), in
  // the fixed stage order from spec §2.1
  const toolOrder = exec.map((c) => c.args[1])
  expect(toolOrder).toEqual(["subfinder", "httpx", "nmap", "nuclei", "ffuf", "sqlmap"])

  const subfinder = exec[0].args
  expect(subfinder.slice(0, 6)).toEqual([
    subfinder[0], "subfinder", "--target", "acme.io", "--data-dir", root,
  ])
  expect(subfinder[0].endsWith("bin/bh-exec.mjs") || subfinder[0].endsWith("bin\\bh-exec.mjs")).toBe(true)
  expect(subfinder.slice(6)).toEqual(["--", "-silent", "-json"])

  const httpx = exec[1].args
  expect(httpx.slice(1, 6)).toEqual(["httpx", "--target", "http://acme.io", "--data-dir", root])
  expect(httpx.slice(6)).toEqual(["--", "-silent", "-json", "-td", "-title", "-sc"])

  const nmap = exec[2].args
  expect(nmap.slice(1, 6)).toEqual(["nmap", "--target", "acme.io", "--data-dir", root])
  expect(nmap.slice(6)).toEqual(["--", "-sT", "-Pn", "-T3", "-p", "80,443,22,8080,8443", "-oG", "-"])

  const nuclei = exec[3].args
  expect(nuclei.slice(1, 6)).toEqual(["nuclei", "--target", "http://acme.io/search?q=x", "--data-dir", root])
  expect(nuclei.slice(6)).toEqual([
    "--", "-silent", "-jsonl", "-disable-update-check", "-severity", "info,low,medium,high,critical", "-c", "25", "-rl", "150",
  ])

  const ffuf = exec[4].args
  expect(ffuf.slice(1, 6)).toEqual(["ffuf", "--target", "http://acme.io/search?q=x/FUZZ", "--data-dir", root])
  expect(ffuf.slice(6)).toEqual([
    "--", "-w", "/usr/share/boundhound/wordlists/common.txt", "-mc", "200,204,301,302,401,403", "-t", "40", "-o", "/dev/stdout", "-of", "json", "-s",
  ])

  const sqlmap = exec[5].args
  expect(sqlmap.slice(1, 6)).toEqual(["sqlmap", "--target", "http://acme.io/search?q=x", "--data-dir", root])
  expect(sqlmap.slice(6)).toEqual(["--", "--batch", "--level", "1", "--risk", "1", "--dbs", "-p", "q"])

  // every bh-exec call passes the same node executable + always names the
  // repo's bh-exec.mjs
  for (const c of exec) {
    expect(c.cmd).toBe("node")
    expect(c.args[0]).toMatch(/bh-exec\.mjs$/)
  }
})

test("valid engagement -> invokes the synth CLIs in the right order (recon-map x3, enum-map x2, exploit-map, findings, report)", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  await runFullscan({ dataDir: root, spawn: fakeSpawn(calls) })

  const synth = synthCalls(calls)
  const bins = synth.map((c) => c.args[0].split("/").pop())
  expect(bins).toEqual([
    "bh-recon-map.mjs",
    "bh-recon-map.mjs",
    "bh-recon-map.mjs",
    "bh-enum-map.mjs",
    "bh-enum-map.mjs",
    "bh-exploit-map.mjs",
    "bh-findings.mjs",
    "bh-report.mjs",
  ])
  // every synth CLI gets the same --data-dir wiring
  for (const c of synth) {
    expect(c.args.slice(1)).toEqual(["--data-dir", root])
  }
})

test("--no-exploit omits the sqlmap bh-exec call AND the exploit-map synth call", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls), exploit: false })

  expect(r.code).toBe(0)
  const exec = execCalls(calls)
  expect(exec.map((c) => c.args[1])).toEqual(["subfinder", "httpx", "nmap", "nuclei", "ffuf"])

  const synth = synthCalls(calls)
  const bins = synth.map((c) => c.args[0].split("/").pop())
  expect(bins).not.toContain("bh-exploit-map.mjs")
  expect(bins).toEqual([
    "bh-recon-map.mjs", "bh-recon-map.mjs", "bh-recon-map.mjs", "bh-enum-map.mjs", "bh-enum-map.mjs", "bh-findings.mjs", "bh-report.mjs",
  ])
})

test("captured stdout is written to the stage's output file where the map-builders read from", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  await runFullscan({ dataDir: root, spawn: fakeSpawn(calls, { stdout: "line-1\n" }) })

  expect(readFileSync(join(outputDir, "recon", "subfinder.jsonl"), "utf8")).toContain("line-1")
  expect(readFileSync(join(outputDir, "recon", "httpx.jsonl"), "utf8")).toContain("line-1")
  expect(readFileSync(join(outputDir, "recon", "acme.io.gnmap"), "utf8")).toContain("line-1")
  expect(readFileSync(join(outputDir, "enum", "nuclei-acme.io.jsonl"), "utf8")).toContain("line-1")
  expect(existsSync(join(outputDir, "enum", "ffuf-acme.io.json"))).toBe(true)
  expect(readFileSync(join(outputDir, "exploit", "acme.io.sqlmap.txt"), "utf8")).toContain("line-1")
})

test("a bh-exec DENY (exit 2) is logged and skipped, not fatal -- other steps still run", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const logLines = []
  const spawn = (cmd, args, opts) => {
    calls.push({ cmd, args })
    if (args[1] === "nmap") return { status: 2, stdout: "", stderr: "" }
    return { status: 0, stdout: "ok\n", stderr: "" }
  }

  const r = await runFullscan({ dataDir: root, spawn, log: (l) => logLines.push(l) })

  expect(r.code).toBe(0)
  // nmap was attempted...
  expect(execCalls(calls).some((c) => c.args[1] === "nmap")).toBe(true)
  // ...but produced no output file...
  expect(existsSync(join(outputDir, "recon", "acme.io.gnmap"))).toBe(false)
  // ...and every later stage still ran
  expect(execCalls(calls).some((c) => c.args[1] === "sqlmap")).toBe(true)
  expect(logLines.some((l) => l.includes("DENY") && l.includes("nmap"))).toBe(true)
})
