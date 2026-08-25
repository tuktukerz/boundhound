// bin/bh-fullscan.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs"
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

function seedReconMap(map = RECON_MAP) {
  const reconDir = join(outputDir, "recon")
  mkdirSync(reconDir, { recursive: true })
  writeFileSync(join(reconDir, "recon-map.json"), JSON.stringify(map))
}

function seedEnumMap(map) {
  const enumDir = join(outputDir, "enum")
  mkdirSync(enumDir, { recursive: true })
  writeFileSync(join(enumDir, "enum-map.json"), JSON.stringify(map))
}

// Two http_services on the SAME host (acme.io), each with a distinct query
// param -- reproduces the real-world shape that makes ffuf plan >1 step for
// one host (and, via exploit:sqlmap's enumMap.content candidates below,
// makes sqlmap do the same).
const RECON_MAP_TWO_HTTP_SERVICES = {
  generated_at: "2026-08-25T00:00:00.000Z",
  subdomains: [],
  http_services: [
    { url: "http://acme.io/search?q=x", host: "acme.io", status_code: 200, title: "t1", tech: [] },
    { url: "http://acme.io/login?user=y", host: "acme.io", status_code: 200, title: "t2", tech: [] },
  ],
  hosts: [
    { host: "acme.io", ports: [{ port: 80, proto: "tcp", state: "open", service: "http" }] },
  ],
}

// enum-map.json content carrying a SECOND distinct param-URL on the same
// host as RECON_MAP's single http_service -- this is exactly how ffuf's
// match results (enumMap.content) give exploit:sqlmap a second candidate
// URL for a host recon-map only ever saw one URL for (the false claim the
// old OUTPUT_RULES comment made).
const ENUM_MAP_EXTRA_SQLMAP_TARGET = {
  generated_at: "2026-08-25T00:00:00.000Z",
  content: [{ url: "http://acme.io/login?user=y", path: "login", status: 200, length: 10, words: 2, host: "acme.io" }],
  findings: [],
  by_severity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
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
  // ffuf keeps "write" mode but its filename now carries a per-host step
  // counter (started in this fix) so a single-step run produces
  // "ffuf-<host>-1.json" rather than the old "ffuf-<host>.json".
  expect(existsSync(join(outputDir, "enum", "ffuf-acme.io-1.json"))).toBe(true)
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

// --- output-file collision regressions (no two steps' stdout may overwrite
// each other within a single run) -----------------------------------------

test("exploit:sqlmap plans 2 steps for the same host -> append mode keeps BOTH steps' stdout, not just the last", async () => {
  writeScope(VALID_SCOPE)
  // RECON_MAP's own http_service ("...search?q=x") plus enumMap.content's
  // extra url ("...login?user=y") are two DISTINCT candidate URLs on the
  // SAME host (acme.io), each carrying a query param -> targetsForStage
  // plans 2 sqlmap steps, neither collapsed by dedupe() (the urls differ).
  seedReconMap()
  seedEnumMap(ENUM_MAP_EXTRA_SQLMAP_TARGET)

  const calls = []
  const spawn = (cmd, args) => {
    calls.push({ cmd, args })
    if (args[1] === "sqlmap") {
      const target = args[3]
      return { status: 0, stdout: `sqlmap-output-for::${target}\n`, stderr: "" }
    }
    return { status: 0, stdout: "generic-output\n", stderr: "" }
  }

  const r = await runFullscan({ dataDir: root, spawn })
  expect(r.code).toBe(0)

  const sqlmapCalls = execCalls(calls).filter((c) => c.args[1] === "sqlmap")
  expect(sqlmapCalls.length).toBe(2)
  const targets = sqlmapCalls.map((c) => c.args[3])
  expect(new Set(targets).size).toBe(2) // both steps target the same host but distinct urls

  // Both steps write into the SAME <host>.sqlmap.txt (keyed on host alone) --
  // with the old "write" mode, only the second step's stdout would survive.
  const sqlmapOut = readFileSync(join(outputDir, "exploit", "acme.io.sqlmap.txt"), "utf8")
  for (const t of targets) {
    expect(sqlmapOut).toContain(`sqlmap-output-for::${t}`)
  }
})

test("enum:ffuf plans 2 steps for the same host -> each step lands in its own distinct file, no overwrite", async () => {
  writeScope(VALID_SCOPE)
  // Two http_services on the same host -> enum:ffuf plans 2 steps for
  // acme.io (liveHttpServiceUrls yields one url per service, unfiltered by
  // dedupe since the urls themselves differ).
  seedReconMap(RECON_MAP_TWO_HTTP_SERVICES)

  const calls = []
  const spawn = (cmd, args) => {
    calls.push({ cmd, args })
    if (args[1] === "ffuf") {
      const target = args[3]
      return { status: 0, stdout: `ffuf-marker::${target}\n`, stderr: "" }
    }
    return { status: 0, stdout: "generic-output\n", stderr: "" }
  }

  const r = await runFullscan({ dataDir: root, spawn })
  expect(r.code).toBe(0)

  const ffufCalls = execCalls(calls).filter((c) => c.args[1] === "ffuf")
  expect(ffufCalls.length).toBe(2)
  const targets = ffufCalls.map((c) => c.args[3])
  expect(new Set(targets).size).toBe(2)

  const enumDir = join(outputDir, "enum")
  const ffufFiles = readdirSync(enumDir).filter((f) => f.startsWith("ffuf") && f.endsWith(".json")).sort()
  // TWO distinct files, one per step -- the deterministic per-host counter
  // in makeRunner's closure disambiguates the filename.
  expect(ffufFiles).toEqual(["ffuf-acme.io-1.json", "ffuf-acme.io-2.json"])

  const contents = ffufFiles.map((f) => readFileSync(join(enumDir, f), "utf8"))
  expect(contents[0]).not.toBe(contents[1])
  expect(contents[0]).toContain(`ffuf-marker::${targets[0]}`)
  expect(contents[1]).toContain(`ffuf-marker::${targets[1]}`)
})
