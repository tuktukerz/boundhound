// src/orchestrate/fullscan.test.mjs
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { targetsForStage, runFullscan } from "./fullscan.mjs"
import { stepKey, emptyState, isDone, markDone } from "./run-state.mjs"

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

// Regression: a domain carved OUT of a broader wildcard (a normal scope
// shape -- "*.acme.io" in scope, bare apex "acme.io" explicitly excluded)
// must never leak into recon:httpx's derived host list. rootDomains() strips
// "*." to produce the root "acme.io", which is simultaneously listed
// out_of_scope -- matchTarget must DENY it, and every stage's final host
// list must reflect that DENY, not just subfinder/nmap's.
test("recon:httpx -> a root domain carved out via out_of_scope is excluded (no out-of-scope leak)", () => {
  const carveOutScope = {
    in_scope: { domains: ["*.acme.io"], cidrs: [] },
    out_of_scope: { domains: ["acme.io"], cidrs: [] },
  }
  const reconMapWithSubdomain = { ...reconMap, hosts: [] }

  const subfinderSteps = targetsForStage("recon:subfinder", { reconMap: reconMapWithSubdomain, enumMap }, carveOutScope)
  const httpxSteps = targetsForStage("recon:httpx", { reconMap: reconMapWithSubdomain, enumMap }, carveOutScope)
  const nmapSteps = targetsForStage("recon:nmap", { reconMap: reconMapWithSubdomain, enumMap }, carveOutScope)

  // subfinder/nmap already correctly excluded the carved-out apex
  expect(subfinderSteps.some((s) => s.target === "acme.io")).toBe(false)
  expect(nmapSteps.some((s) => s.target === "acme.io")).toBe(false)
  // httpx must match -- no step for the excluded apex, and no step at all
  // whose target is built from it (http://acme.io)
  expect(httpxSteps.some((s) => s.target === "http://acme.io")).toBe(false)
  expect(httpxSteps.every((s) => s.target !== "http://acme.io")).toBe(true)

  // api.acme.io (a real subdomain of the carved-out apex) still clears scope
  // via the *.acme.io wildcard and must still be planned -- the fix must not
  // over-exclude
  expect(httpxSteps).toEqual([{ tool: "httpx", target: "http://api.acme.io", flags: ["-silent", "-json", "-td", "-title", "-sc"] }])
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

// --- O3: resume / retry / budget (Phase 7 resilience) -----------------------

test("runFullscan: back-compat -- no new params behaves exactly as before; new summary fields default neutral", async () => {
  const mocks = makeMocks()
  const summary = await runFullscan({ runner: mocks.runner, synth: mocks.synth, loadMaps: mocks.loadMaps, scope, log: mocks.log })

  expect(summary.toolsRun).toBe(11)
  expect(summary.reportGenerated).toBe(true)
  expect(summary.resumedSkipped).toBe(0)
  expect(summary.retried).toBe(0)
  expect(summary.budgetStopped).toBeFalsy()
})

test("runFullscan: resume -- pre-seeded done step is skipped (runner not called for it), remaining steps run, saveState called per completed unit, resumedSkipped counted", async () => {
  const doneKey = stepKey({ stage: "recon:subfinder", tool: "subfinder", target: "acme.io" })
  const seedState = markDone(emptyState(), doneKey)

  const runnerCalls = []
  const runner = async (step) => {
    runnerCalls.push(step)
    return { status: "ok" }
  }
  const synth = async () => {}
  const loadMaps = async () => ({ reconMap, enumMap })
  const loadState = async () => seedState
  const saveStateCalls = []
  const saveState = async (state) => {
    saveStateCalls.push(state)
  }
  const logLines = []
  const log = (l) => logLines.push(l)

  const summary = await runFullscan({ runner, synth, loadMaps, scope, log, loadState, saveState }, { resume: true })

  // the pre-marked-done subfinder step was never invoked
  expect(runnerCalls.some((c) => c.tool === "subfinder")).toBe(false)
  // everything else still ran
  expect(runnerCalls.some((c) => c.tool === "httpx")).toBe(true)
  expect(runnerCalls.some((c) => c.tool === "nmap")).toBe(true)
  expect(runnerCalls.some((c) => c.tool === "nuclei")).toBe(true)
  expect(runnerCalls.some((c) => c.tool === "ffuf")).toBe(true)
  expect(runnerCalls.some((c) => c.tool === "sqlmap")).toBe(true)

  expect(summary.resumedSkipped).toBe(1)
  // saveState called once per completed (ok/denied) step
  expect(saveStateCalls.length).toBe(runnerCalls.length)
  expect(logLines.some((l) => l.includes("resume: skip"))).toBe(true)
})

test("runFullscan: resume=false (default) -- loadState/saveState are never called even if provided", async () => {
  let loadCalled = false
  let saveCalled = false
  const loadState = async () => {
    loadCalled = true
    return emptyState()
  }
  const saveState = async () => {
    saveCalled = true
  }
  const mocks = makeMocks()
  await runFullscan({ runner: mocks.runner, synth: mocks.synth, loadMaps: mocks.loadMaps, scope, log: mocks.log, loadState, saveState })

  expect(loadCalled).toBe(false)
  expect(saveCalled).toBe(false)
})

test("runFullscan: retry -- transient retried up to maxRetries then ok; injected sleep counted; summary.retried correct", async () => {
  const sleepCalls = []
  const sleep = async (ms) => {
    sleepCalls.push(ms)
  }
  let subfinderCalls = 0
  const runner = async (step) => {
    if (step.tool === "subfinder") {
      subfinderCalls++
      if (subfinderCalls <= 2) return { status: "transient" }
      return { status: "ok" }
    }
    return { status: "ok" }
  }
  const synth = async () => {}
  const loadMaps = async () => ({ reconMap, enumMap })
  const logLines = []
  const log = (l) => logLines.push(l)

  const summary = await runFullscan(
    { runner, synth, loadMaps, scope, log, sleep },
    { retry: { maxRetries: 3, backoff: (attempt) => (attempt + 1) * 10 } }
  )

  expect(subfinderCalls).toBe(3) // 2 transient + 1 ok
  expect(sleepCalls).toEqual([10, 20])
  expect(summary.retried).toBe(2)
  expect(logLines.some((l) => l.toLowerCase().includes("transient") || l.toLowerCase().includes("retry"))).toBe(true)
})

test("runFullscan: retry -- a denied outcome is NEVER retried and IS markDone'd", async () => {
  let subfinderCalls = 0
  const runner = async (step) => {
    if (step.tool === "subfinder") {
      subfinderCalls++
      return { status: "denied" }
    }
    return { status: "ok" }
  }
  const sleepCalls = []
  const sleep = async (ms) => sleepCalls.push(ms)
  const synth = async () => {}
  const loadMaps = async () => ({ reconMap, enumMap })
  const loadState = async () => emptyState()
  let savedState = null
  const saveState = async (state) => {
    savedState = state
  }
  const log = () => {}

  const summary = await runFullscan(
    { runner, synth, loadMaps, scope, log, sleep, loadState, saveState },
    { resume: true, retry: { maxRetries: 5, backoff: () => 1 } }
  )

  expect(subfinderCalls).toBe(1) // never retried despite maxRetries:5
  expect(sleepCalls).toEqual([]) // denied never triggers backoff/sleep
  expect(summary.retried).toBe(0)
  const key = stepKey({ stage: "recon:subfinder", tool: "subfinder", target: "acme.io" })
  expect(isDone(savedState, key)).toBe(true)
})

test("runFullscan: retry -- maxRetries:0 (default) + a throwing runner reproduces today's skip-not-fatal", async () => {
  const mocks = makeMocks({ failOn: (step) => step.tool === "httpx" && step.target === "http://acme.io" })
  const sleepCalls = []
  const sleep = async (ms) => sleepCalls.push(ms)

  const summary = await runFullscan(
    { runner: mocks.runner, synth: mocks.synth, loadMaps: mocks.loadMaps, scope, log: mocks.log, sleep },
    { retry: { maxRetries: 0 } }
  )

  expect(mocks.runnerCalls.some((c) => c.tool === "httpx" && c.target === "http://acme.io")).toBe(true)
  expect(mocks.runnerCalls.some((c) => c.tool === "nmap")).toBe(true)
  expect(mocks.runnerCalls.some((c) => c.tool === "sqlmap")).toBe(true)
  expect(sleepCalls).toEqual([])
  expect(summary.retried).toBe(0)
  expect(summary.reportGenerated).toBe(true)
  expect(mocks.logLines.some((l) => l.includes("denied") || l.includes("http://acme.io"))).toBe(true)
})

test("runFullscan: budget.maxSteps stops all further work; findings+report still run; budgetStopped set", async () => {
  const runnerCalls = []
  const runner = async (step) => {
    runnerCalls.push(step)
    return { status: "ok" }
  }
  const synthCalls = []
  const synth = async (kind) => synthCalls.push(kind)
  const loadMaps = async () => ({ reconMap, enumMap })
  const logLines = []
  const log = (l) => logLines.push(l)

  const summary = await runFullscan({ runner, synth, loadMaps, scope, log }, { budget: { maxSteps: 1 } })

  expect(runnerCalls.length).toBe(1)
  expect(synthCalls.slice(-2)).toEqual(["findings", "report"])
  expect(summary.reportGenerated).toBe(true)
  expect(summary.budgetStopped).toBeTruthy()
  expect(logLines.some((l) => l.includes("budget"))).toBe(true)
})

// Regression: a mid-stage maxSteps cutoff (as opposed to hitting the ceiling
// exactly at a stage boundary) must still synth the INTERRUPTED stage before
// stopping -- steps that already ran in that stage wrote real output that
// only that stage's own synth turns into recon-map/enum-map/exploit-map.json
// (what findings/report read). recon:subfinder plans 1 step, recon:httpx
// plans 2 -- maxSteps:2 is exhausted after httpx's FIRST step, mid-stage.
test("runFullscan: budget.maxSteps mid-stage cutoff still synths the interrupted stage before stopping", async () => {
  const runnerCalls = []
  const runner = async (step) => {
    runnerCalls.push(step)
    return { status: "ok" }
  }
  const synthCalls = []
  const synth = async (kind) => synthCalls.push(kind)
  const loadMaps = async () => ({ reconMap, enumMap })
  const log = () => {}

  const summary = await runFullscan({ runner, synth, loadMaps, scope, log }, { budget: { maxSteps: 2 } })

  expect(runnerCalls.length).toBe(2)
  expect(runnerCalls.map((c) => c.stage)).toEqual(["recon:subfinder", "recon:httpx"])

  // the interrupted stage (recon:httpx) still got its own summary entry...
  expect(summary.stages.find((s) => s.stage === "recon:httpx")).toEqual({ stage: "recon:httpx", steps: 2 })
  // ...and its own synth: "recon-map" must appear TWICE (subfinder's + the
  // interrupted httpx's), not once -- once is what an immediate
  // `break outerStages` from inside the per-step loop would produce
  expect(synthCalls.filter((k) => k === "recon-map")).toHaveLength(2)

  // later stages never ran at all
  expect(runnerCalls.some((c) => c.stage === "recon:nmap")).toBe(false)
  expect(summary.stages.some((s) => s.stage === "recon:nmap")).toBe(false)

  // findings+report still ran at the very end
  expect(synthCalls.slice(-2)).toEqual(["findings", "report"])
  expect(summary.reportGenerated).toBe(true)
  expect(summary.budgetStopped).toBeTruthy()
})

test("runFullscan: budget.maxSteps:0 stops all work immediately (typeof-number gate, not truthiness)", async () => {
  const runnerCalls = []
  const runner = async (step) => {
    runnerCalls.push(step)
    return { status: "ok" }
  }
  const synthCalls = []
  const synth = async (kind) => synthCalls.push(kind)
  const loadMaps = async () => ({ reconMap, enumMap })
  const log = () => {}

  const summary = await runFullscan({ runner, synth, loadMaps, scope, log }, { budget: { maxSteps: 0 } })

  expect(runnerCalls).toHaveLength(0)
  expect(summary.stages).toEqual([])
  expect(synthCalls).toEqual(["findings", "report"])
  expect(summary.reportGenerated).toBe(true)
  expect(summary.budgetStopped).toBeTruthy()
})

test("runFullscan: budget.maxStepsPerStage caps each stage but every stage still proceeds", async () => {
  const runnerCalls = []
  const runner = async (step) => {
    runnerCalls.push(step)
    return { status: "ok" }
  }
  const synthCalls = []
  const synth = async (kind) => synthCalls.push(kind)
  const loadMaps = async () => ({ reconMap, enumMap })
  const log = () => {}

  const summary = await runFullscan({ runner, synth, loadMaps, scope, log }, { budget: { maxStepsPerStage: 1 } })

  const perStage = {}
  for (const c of runnerCalls) perStage[c.stage] = (perStage[c.stage] || 0) + 1
  expect(Object.keys(perStage)).toHaveLength(6) // all 6 stages still attempted
  for (const stage of Object.keys(perStage)) {
    expect(perStage[stage]).toBe(1)
  }
  expect(synthCalls.slice(-2)).toEqual(["findings", "report"])
  expect(summary.budgetStopped).toBeFalsy()
})
