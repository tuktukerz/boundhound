// src/orchestrate/fullscan.test.mjs
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { targetsForStage, runFullscan } from "./fullscan.mjs"

const fixturesDir = join(import.meta.dir, "..", "..", "test", "fixtures", "orchestrate")
const reconMap = JSON.parse(readFileSync(join(fixturesDir, "recon-map.json"), "utf8"))
const enumMap = JSON.parse(readFileSync(join(fixturesDir, "enum-map.json"), "utf8"))

// "acme.io" is a literal root (subfinder/httpx/nmap target); "*.acme.io"
// exists purely to clear discovered subdomains (per pentest-recon's
// *.<domain> rule) -- api.acme.io clears it, evil.com does not (and is also
// explicitly listed out_of_scope, so it's DENYd twice over).
const scope = {
  in_scope: { domains: ["acme.io", "*.acme.io"], cidrs: [] },
  out_of_scope: { domains: ["evil.com"], cidrs: ["10.0.0.0/8"] },
}

const STAGES = ["recon:subfinder", "recon:httpx", "recon:nmap", "enum:nuclei", "enum:ffuf", "exploit:sqlmap"]

// --- O1: targetsForStage (pure planner) -------------------------------------

test("recon:subfinder -> one step per deduped in-scope root domain", () => {
  const steps = targetsForStage("recon:subfinder", { reconMap, enumMap }, scope)
  expect(steps).toEqual([{ tool: "subfinder", target: "acme.io", flags: ["-silent", "-json"] }])
})

test("recon:httpx -> roots + in-scope discovered subdomains; out-of-scope subdomain excluded", () => {
  const steps = targetsForStage("recon:httpx", { reconMap, enumMap }, scope)
  expect(steps).toEqual([
    { tool: "httpx", target: "http://acme.io", flags: ["-silent", "-json", "-td", "-title", "-sc"] },
    { tool: "httpx", target: "http://api.acme.io", flags: ["-silent", "-json", "-td", "-title", "-sc"] },
  ])
  expect(steps.some((s) => s.target.includes("evil.com"))).toBe(false)
})

test("recon:nmap -> reconMap.hosts + discovered in-scope hosts, deduped; out-of-scope host never appears", () => {
  const steps = targetsForStage("recon:nmap", { reconMap, enumMap }, scope)
  expect(steps).toEqual([
    { tool: "nmap", target: "acme.io", flags: ["-sT", "-Pn", "-T3", "-p", "80,443,22,8080,8443", "-oG", "-"] },
    { tool: "nmap", target: "api.acme.io", flags: ["-sT", "-Pn", "-T3", "-p", "80,443,22,8080,8443", "-oG", "-"] },
  ])
  expect(steps.some((s) => s.target === "evil.com")).toBe(false)
})

test("enum:nuclei -> one step per in-scope reconMap.http_services url", () => {
  const steps = targetsForStage("enum:nuclei", { reconMap, enumMap }, scope)
  expect(steps).toEqual([
    {
      tool: "nuclei",
      target: "http://acme.io",
      flags: ["-silent", "-jsonl", "-disable-update-check", "-severity", "info,low,medium,high,critical", "-c", "25", "-rl", "150"],
    },
    {
      tool: "nuclei",
      target: "http://api.acme.io/item?id=1",
      flags: ["-silent", "-jsonl", "-disable-update-check", "-severity", "info,low,medium,high,critical", "-c", "25", "-rl", "150"],
    },
  ])
})

test("enum:ffuf -> one step per live http service url, FUZZ-suffixed", () => {
  const steps = targetsForStage("enum:ffuf", { reconMap, enumMap }, scope)
  expect(steps).toEqual([
    {
      tool: "ffuf",
      target: "http://acme.io/FUZZ",
      flags: ["-w", "/usr/share/boundhound/wordlists/common.txt", "-mc", "200,204,301,302,401,403", "-t", "40", "-o", "/dev/stdout", "-of", "json", "-s"],
    },
    {
      tool: "ffuf",
      target: "http://api.acme.io/item?id=1/FUZZ",
      flags: ["-w", "/usr/share/boundhound/wordlists/common.txt", "-mc", "200,204,301,302,401,403", "-t", "40", "-o", "/dev/stdout", "-of", "json", "-s"],
    },
  ])
})

test("exploit:sqlmap -> a param URL (recon http_services) produces a step with -p <first param name>", () => {
  const steps = targetsForStage("exploit:sqlmap", { reconMap, enumMap }, scope)
  const step = steps.find((s) => s.target === "http://api.acme.io/item?id=1")
  expect(step).toEqual({
    tool: "sqlmap",
    target: "http://api.acme.io/item?id=1",
    flags: ["--batch", "--level", "1", "--risk", "1", "--dbs", "-p", "id"],
  })
})

test("exploit:sqlmap -> a param URL from enum-map content also produces a step", () => {
  const steps = targetsForStage("exploit:sqlmap", { reconMap, enumMap }, scope)
  const step = steps.find((s) => s.target === "http://acme.io/search?q=test")
  expect(step).toEqual({
    tool: "sqlmap",
    target: "http://acme.io/search?q=test",
    flags: ["--batch", "--level", "1", "--risk", "1", "--dbs", "-p", "q"],
  })
})

test("exploit:sqlmap -> URLs with no query param produce NO step", () => {
  const steps = targetsForStage("exploit:sqlmap", { reconMap, enumMap }, scope)
  const targets = steps.map((s) => s.target)
  expect(targets).not.toContain("http://acme.io")
  expect(targets).not.toContain("http://acme.io/robots.txt")
  expect(steps).toHaveLength(2)
})

test("targetsForStage: unknown stage name -> [] not throw", () => {
  expect(() => targetsForStage("bogus:stage", { reconMap, enumMap }, scope)).not.toThrow()
  expect(targetsForStage("bogus:stage", { reconMap, enumMap }, scope)).toEqual([])
})

test("targetsForStage: empty maps + empty scope -> [] for every stage, never throws", () => {
  for (const stage of STAGES) {
    expect(() => targetsForStage(stage, {}, {})).not.toThrow()
    expect(targetsForStage(stage, {}, {})).toEqual([])
  }
})

test("targetsForStage: missing/garbage maps and scope -> [] for every stage, never throws", () => {
  for (const stage of STAGES) {
    expect(() => targetsForStage(stage, undefined, undefined)).not.toThrow()
    expect(targetsForStage(stage, undefined, undefined)).toEqual([])

    expect(() => targetsForStage(stage, { reconMap: "garbage", enumMap: 42 }, { in_scope: "nope" })).not.toThrow()
    expect(targetsForStage(stage, { reconMap: "garbage", enumMap: 42 }, { in_scope: "nope" })).toEqual([])

    expect(() =>
      targetsForStage(
        stage,
        { reconMap: { hosts: "x", http_services: [1, null], subdomains: [null, 5] }, enumMap: { content: "x" } },
        null
      )
    ).not.toThrow()
  }
})

test("targetsForStage: same input twice -> identical output (deterministic)", () => {
  const a = targetsForStage("recon:httpx", { reconMap, enumMap }, scope)
  const b = targetsForStage("recon:httpx", { reconMap, enumMap }, scope)
  expect(a).toEqual(b)
})

// --- O2: runFullscan (injectable staged driver) -----------------------------

function makeMocks({ failOn } = {}) {
  const runnerCalls = []
  const synthCalls = []
  const logLines = []
  const runner = async (step) => {
    runnerCalls.push(step)
    if (failOn && failOn(step)) throw new Error(`denied: ${step.tool} ${step.target}`)
    return { ok: true }
  }
  const synth = async (kind) => {
    synthCalls.push(kind)
  }
  const loadMaps = async () => ({ reconMap, enumMap })
  const log = (line) => logLines.push(line)
  return { runnerCalls, synthCalls, logLines, runner, synth, loadMaps, log }
}

test("runFullscan: runs stages in fixed order, runner per step, synth per stage, findings+report last", async () => {
  const mocks = makeMocks()
  const summary = await runFullscan({ runner: mocks.runner, synth: mocks.synth, loadMaps: mocks.loadMaps, scope, log: mocks.log })

  // synth calls: recon-map x3, enum-map x2, exploit-map x1, then findings, report
  expect(mocks.synthCalls).toEqual([
    "recon-map",
    "recon-map",
    "recon-map",
    "enum-map",
    "enum-map",
    "exploit-map",
    "findings",
    "report",
  ])

  // runner called once per planned step, stage order preserved, stage field stamped on each call
  const stagesSeen = [...new Set(mocks.runnerCalls.map((c) => c.stage))]
  expect(stagesSeen).toEqual(STAGES)
  expect(mocks.runnerCalls.every((c) => typeof c.tool === "string" && typeof c.target === "string" && Array.isArray(c.flags))).toBe(true)

  expect(summary.reportGenerated).toBe(true)
  expect(summary.stages).toEqual([
    { stage: "recon:subfinder", steps: 1 },
    { stage: "recon:httpx", steps: 2 },
    { stage: "recon:nmap", steps: 2 },
    { stage: "enum:nuclei", steps: 2 },
    { stage: "enum:ffuf", steps: 2 },
    { stage: "exploit:sqlmap", steps: 2 },
  ])
  expect(summary.toolsRun).toBe(11)
  expect(summary.toolsRun).toBe(summary.stages.reduce((n, s) => n + s.steps, 0))
})

test("runFullscan: a throwing runner step is skipped, not fatal -- later steps/stages still run", async () => {
  const mocks = makeMocks({ failOn: (step) => step.tool === "httpx" && step.target === "http://acme.io" })
  const summary = await runFullscan({ runner: mocks.runner, synth: mocks.synth, loadMaps: mocks.loadMaps, scope, log: mocks.log })

  // the failing step was still attempted...
  expect(mocks.runnerCalls.some((c) => c.tool === "httpx" && c.target === "http://acme.io")).toBe(true)
  // ...and the OTHER httpx step in the same stage still ran
  expect(mocks.runnerCalls.some((c) => c.tool === "httpx" && c.target === "http://api.acme.io")).toBe(true)
  // ...and every later stage still ran (nmap depends on nothing from httpx's runner outcome here since loadMaps is mocked constant)
  expect(mocks.runnerCalls.some((c) => c.tool === "nmap")).toBe(true)
  expect(mocks.runnerCalls.some((c) => c.tool === "sqlmap")).toBe(true)

  // findings/report still synthesized
  expect(mocks.synthCalls.slice(-2)).toEqual(["findings", "report"])
  expect(summary.reportGenerated).toBe(true)
  // the throw did not shrink the reported step count for that stage
  expect(summary.stages.find((s) => s.stage === "recon:httpx")).toEqual({ stage: "recon:httpx", steps: 2 })
  expect(summary.toolsRun).toBe(11)

  expect(mocks.logLines.some((l) => l.includes("denied") || l.includes("http://acme.io"))).toBe(true)
})

test("runFullscan: a throwing loadMaps/synth call is also skipped, not fatal", async () => {
  const runnerCalls = []
  const runner = async (step) => runnerCalls.push(step)
  let synthCallCount = 0
  const synth = async (kind) => {
    synthCallCount++
    if (kind === "enum-map") throw new Error("synth boom")
  }
  let loadCallCount = 0
  const loadMaps = async () => {
    loadCallCount++
    if (loadCallCount === 1) throw new Error("loadMaps boom")
    return { reconMap, enumMap }
  }
  const logLines = []
  const summary = await runFullscan({ runner, synth, loadMaps, scope, log: (l) => logLines.push(l) })

  // overall run completes and still reaches the end
  expect(summary.reportGenerated).toBe(true)
  // first stage saw a loadMaps failure -> treated as empty maps -> recon:subfinder still
  // works off scope alone, so it is NOT necessarily empty; the key guarantee is no throw
  expect(Array.isArray(summary.stages)).toBe(true)
  expect(logLines.length).toBeGreaterThan(0)
})

test("runFullscan: a stage with no derived targets is skipped (logged), not run or synthesized", async () => {
  const reconMapNoParams = { ...reconMap, http_services: [{ url: "http://acme.io", host: "acme.io", status_code: 200, title: "x", tech: [] }] }
  const enumMapNoParams = { ...enumMap, content: [{ url: "http://acme.io/robots.txt", path: "robots.txt", status: 200, length: 1, host: "acme.io" }] }

  const runnerCalls = []
  const synthCalls = []
  const logLines = []
  const runner = async (step) => runnerCalls.push(step)
  const synth = async (kind) => synthCalls.push(kind)
  const loadMaps = async () => ({ reconMap: reconMapNoParams, enumMap: enumMapNoParams })
  const log = (l) => logLines.push(l)

  const summary = await runFullscan({ runner, synth, loadMaps, scope, log })

  // no param URLs anywhere -> exploit:sqlmap has zero steps -> skipped entirely
  expect(runnerCalls.some((c) => c.tool === "sqlmap")).toBe(false)
  expect(synthCalls).not.toContain("exploit-map")
  expect(summary.stages.find((s) => s.stage === "exploit:sqlmap")).toEqual({ stage: "exploit:sqlmap", steps: 0 })
  // findings/report still run at the very end regardless
  expect(synthCalls.slice(-2)).toEqual(["findings", "report"])
  expect(logLines.some((l) => l.toLowerCase().includes("exploit:sqlmap"))).toBe(true)
})

test("runFullscan: exploit:false omits the sqlmap stage entirely (no entry, no run, no synth)", async () => {
  const mocks = makeMocks()
  const summary = await runFullscan(
    { runner: mocks.runner, synth: mocks.synth, loadMaps: mocks.loadMaps, scope, log: mocks.log },
    { exploit: false }
  )

  expect(mocks.runnerCalls.some((c) => c.tool === "sqlmap")).toBe(false)
  expect(mocks.synthCalls).not.toContain("exploit-map")
  expect(summary.stages.some((s) => s.stage === "exploit:sqlmap")).toBe(false)
  expect(summary.stages).toEqual([
    { stage: "recon:subfinder", steps: 1 },
    { stage: "recon:httpx", steps: 2 },
    { stage: "recon:nmap", steps: 2 },
    { stage: "enum:nuclei", steps: 2 },
    { stage: "enum:ffuf", steps: 2 },
  ])
  expect(mocks.synthCalls).toEqual(["recon-map", "recon-map", "recon-map", "enum-map", "enum-map", "findings", "report"])
  expect(summary.toolsRun).toBe(9)
  expect(summary.reportGenerated).toBe(true)
})

test("runFullscan: default (no-op) runner/synth/loadMaps/log -- never throws", async () => {
  await expect(runFullscan({ scope })).resolves.toBeDefined()
  const summary = await runFullscan({ scope })
  expect(summary.reportGenerated).toBe(true)
  expect(Array.isArray(summary.stages)).toBe(true)
})

test("runFullscan: completely empty deps -- never throws", async () => {
  await expect(runFullscan()).resolves.toBeDefined()
  await expect(runFullscan({})).resolves.toBeDefined()
})
