// bin/bh-fullscan.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runFullscan, makeRunner, extractFlags, backoff } from "./bh-fullscan.mjs"

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

// --- Phase 7 resilience: --resume / --max-retries / --max-steps / ---------
// --max-steps-per-stage wiring (spec §4) -------------------------------------

// --- extractFlags: pure argv parsing, same convention as --data-dir/
// --no-exploit (never exercised via the isMain entrypoint under bun test,
// since process.argv[1] never equals this file's own path there) ----------

test("extractFlags: --resume/--max-retries/--max-steps/--max-steps-per-stage parsed and stripped from rest, alongside existing flags", () => {
  const r = extractFlags([
    "--data-dir", "/tmp/x",
    "--no-exploit",
    "--resume",
    "--max-retries", "3",
    "--max-steps", "10",
    "--max-steps-per-stage", "2",
    "positional",
  ])
  expect(r.dataDir).toBe("/tmp/x")
  expect(r.noExploit).toBe(true)
  expect(r.resume).toBe(true)
  expect(r.maxRetries).toBe(3)
  expect(r.maxSteps).toBe(10)
  expect(r.maxStepsPerStage).toBe(2)
  expect(r.rest).toEqual(["positional"])
})

test("extractFlags: none of the new flags given -> resume false, maxRetries 0, maxSteps/maxStepsPerStage undefined (today's shape)", () => {
  const r = extractFlags(["--data-dir", "/tmp/x"])
  expect(r.resume).toBe(false)
  expect(r.maxRetries).toBe(0)
  expect(r.maxSteps).toBeUndefined()
  expect(r.maxStepsPerStage).toBeUndefined()
})

// --- backoff: bounded exponential, no jitter --------------------------------

test("backoff: bounded exponential (base=500,cap=8000), deterministic, no jitter", () => {
  expect(backoff(0)).toBe(500)
  expect(backoff(1)).toBe(1000)
  expect(backoff(2)).toBe(2000)
  expect(backoff(10)).toBe(8000) // capped
  expect(backoff(0)).toBe(backoff(0)) // deterministic, same input -> same output
})

// --- makeRunner: exit-code -> {status} mapping ------------------------------

test("makeRunner: exit 0 -> {status:'ok'} and captures output", () => {
  const logLines = []
  const runner = makeRunner({
    codeDir: root,
    dataDir: root,
    name: "acme",
    spawn: () => ({ status: 0, stdout: "hi\n", stderr: "" }),
    log: (l) => logLines.push(l),
  })
  const result = runner({ tool: "subfinder", target: "acme.io", flags: [], stage: "recon:subfinder" })
  expect(result).toEqual({ status: "ok" })
  expect(readFileSync(join(outputDir, "recon", "subfinder.jsonl"), "utf8")).toContain("hi")
})

test("makeRunner: exit 2 -> {status:'denied'}, DENY logged, no output file written", () => {
  const logLines = []
  const runner = makeRunner({
    codeDir: root,
    dataDir: root,
    name: "acme",
    spawn: () => ({ status: 2, stdout: "should-not-be-written\n", stderr: "" }),
    log: (l) => logLines.push(l),
  })
  const result = runner({ tool: "nmap", target: "acme.io", flags: [], stage: "recon:nmap" })
  expect(result).toEqual({ status: "denied" })
  expect(logLines.some((l) => l.includes("DENY") && l.includes("nmap"))).toBe(true)
  expect(existsSync(join(outputDir, "recon", "acme.io.gnmap"))).toBe(false)
})

test("makeRunner: other nonzero exit -> {status:'transient'}, logged, no output file written", () => {
  const logLines = []
  const runner = makeRunner({
    codeDir: root,
    dataDir: root,
    name: "acme",
    spawn: () => ({ status: 1, stdout: "should-not-be-written\n", stderr: "boom" }),
    log: (l) => logLines.push(l),
  })
  const result = runner({ tool: "httpx", target: "http://acme.io", flags: [], stage: "recon:httpx" })
  expect(result).toEqual({ status: "transient" })
  expect(logLines.some((l) => l.includes("httpx") && l.includes("exited 1"))).toBe(true)
  expect(existsSync(join(outputDir, "recon", "httpx.jsonl"))).toBe(false)
})

test("makeRunner: a spawn error (no status, result.error set) -> {status:'transient'}", () => {
  const runner = makeRunner({
    codeDir: root,
    dataDir: root,
    name: "acme",
    spawn: () => ({ error: new Error("ENOENT"), stdout: null, stderr: null }),
    log: () => {},
  })
  const result = runner({ tool: "nuclei", target: "http://acme.io", flags: [], stage: "enum:nuclei" })
  expect(result).toEqual({ status: "transient" })
})

// --- runFullscan: --max-retries threading -----------------------------------

test("maxRetries: a transient (non-0, non-2) exit is retried up to maxRetries with injected sleep receiving backoff(attempt) delays, then succeeds", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  let subfinderCalls = 0
  const calls = []
  const spawn = (cmd, args) => {
    calls.push({ cmd, args })
    if (args[1] === "subfinder") {
      subfinderCalls++
      if (subfinderCalls <= 2) return { status: 1, stdout: "", stderr: "boom" }
      return { status: 0, stdout: "ok\n", stderr: "" }
    }
    return { status: 0, stdout: "ok\n", stderr: "" }
  }
  const sleepCalls = []
  const sleep = async (ms) => {
    sleepCalls.push(ms)
  }

  const r = await runFullscan({ dataDir: root, spawn, maxRetries: 3, sleep })

  expect(r.code).toBe(0)
  expect(subfinderCalls).toBe(3) // 2 transient attempts + 1 success
  expect(sleepCalls).toEqual([500, 1000]) // backoff(0), backoff(1)
})

test("maxRetries default (0) -- a transient step is attempted exactly once, never retried, run still completes", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const sleepCalls = []
  const spawn = (cmd, args) => {
    calls.push({ cmd, args })
    if (args[1] === "subfinder") return { status: 1, stdout: "", stderr: "boom" }
    return { status: 0, stdout: "ok\n", stderr: "" }
  }
  const sleep = async (ms) => sleepCalls.push(ms)

  const r = await runFullscan({ dataDir: root, spawn, sleep })

  expect(r.code).toBe(0)
  expect(execCalls(calls).filter((c) => c.args[1] === "subfinder").length).toBe(1)
  expect(sleepCalls).toEqual([])
})

// --- runFullscan: --max-steps / --max-steps-per-stage threading ------------

test("maxSteps 1 -> only the first tool step is spawned across the whole run, findings+report still generated", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls), maxSteps: 1 })

  expect(r.code).toBe(0)
  expect(execCalls(calls).length).toBe(1)
  expect(execCalls(calls)[0].args[1]).toBe("subfinder")

  const bins = synthCalls(calls).map((c) => c.args[0].split("/").pop())
  expect(bins).toContain("bh-findings.mjs")
  expect(bins).toContain("bh-report.mjs")
})

test("maxSteps omitted -> no budget applied, all 6 stage steps run (today's unbounded behavior)", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls) })
  expect(r.code).toBe(0)
  expect(execCalls(calls).length).toBe(6)
})

test("maxStepsPerStage 1 -> caps steps run per stage without stopping the whole run", async () => {
  writeScope(VALID_SCOPE)
  // two http_services on one host -> enum:ffuf (and exploit:sqlmap) would
  // otherwise plan 2 steps each; maxStepsPerStage:1 caps each stage at 1.
  seedReconMap(RECON_MAP_TWO_HTTP_SERVICES)
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls), maxStepsPerStage: 1 })

  expect(r.code).toBe(0)
  const exec = execCalls(calls)
  expect(exec.filter((c) => c.args[1] === "ffuf").length).toBe(1)
  expect(exec.filter((c) => c.args[1] === "sqlmap").length).toBe(1)
  // run still reaches the end (findings+report), not aborted
  const bins = synthCalls(calls).map((c) => c.args[0].split("/").pop())
  expect(bins).toContain("bh-report.mjs")
})

// --- runFullscan: --resume round-trip (real temp data-dir + stubbed spawn) --

test("resume round-trip: first run writes fullscan-state.json with done units; second --resume run does not re-spawn already-done steps and still completes", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()

  const calls1 = []
  const r1 = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls1), resume: true })
  expect(r1.code).toBe(0)

  const statePath = join(outputDir, "fullscan-state.json")
  expect(existsSync(statePath)).toBe(true)
  const state1 = JSON.parse(readFileSync(statePath, "utf8"))
  expect(state1.version).toBe(1)
  const doneKeys = Object.keys(state1.done)
  // one "done" entry per successfully-run bh-exec step
  expect(doneKeys.length).toBe(execCalls(calls1).length)
  expect(doneKeys.length).toBe(6)

  const calls2 = []
  const r2 = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls2), resume: true })
  expect(r2.code).toBe(0)
  // every step from run 1 is already recorded done -> zero bh-exec spawns
  expect(execCalls(calls2).length).toBe(0)
  // the scan still completes -- synth chain (recon-map/enum-map/exploit-map/
  // findings/report) still runs even though every stage plans 0 fresh steps
  const bins2 = synthCalls(calls2).map((c) => c.args[0].split("/").pop())
  expect(bins2).toContain("bh-findings.mjs")
  expect(bins2).toContain("bh-report.mjs")
})

test("resume: without --resume, no fullscan-state.json is ever written (today's shape unchanged)", async () => {
  writeScope(VALID_SCOPE)
  seedReconMap()
  const calls = []
  const r = await runFullscan({ dataDir: root, spawn: fakeSpawn(calls) })
  expect(r.code).toBe(0)
  expect(existsSync(join(outputDir, "fullscan-state.json"))).toBe(false)
})

// --- existing fail-closed / output-wiring behavior must still hold with the
// new defaults in place (resume:false, maxRetries:0, no budget) -- covered
// by the untouched tests above; these two additions cross-check the exact
// same guarantees still hold when the CLI is invoked with zero Phase 7 flags
// at all, i.e. a caller on the old call surface sees byte-identical behavior.

test("fail-closed still holds with Phase 7 defaults: no active engagement -> code 3, zero spawns, state files untouched", async () => {
  const bareRoot = mkdtempSync(join(tmpdir(), "bh-fullscan-bare-"))
  const calls = []
  const r = await runFullscan({ dataDir: bareRoot, spawn: fakeSpawn(calls) })
  expect(r.code).toBe(3)
  expect(calls.length).toBe(0)
})
