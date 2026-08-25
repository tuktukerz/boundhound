// test/fullscan-resilience-e2e.test.mjs
//
// REAL end-to-end test for Phase 7's resilience layer (spec §6, E2E row): no
// mocking of docker, the tools, or the bh-exec/bh-fullscan CLIs. Mirrors
// test/fullscan-e2e.test.mjs's harness exactly (docker-availability guard,
// per-pid unique names with a prefix-sweep preemptive cleanup, fail-safe
// afterAll teardown, the dotted-FQDN target trick, subfinder-needs-internet
// rationale) -- see that file's comments for the mechanisms not repeated
// here. Own prefix ("bh-e2eresil") so a fullscan-e2e/recon-e2e/enum-e2e
// suite running concurrently on the same daemon never collides with (or
// gets swept by) this one.
//
// What THIS file proves that fullscan-e2e.test.mjs does not (spec §4/§6):
//
//   (a) --resume really skips already-done work on a second real run. Both
//       runs pass --resume (not just the second): per src/orchestrate/
//       fullscan.mjs + bin/bh-fullscan.mjs, loadState/saveState/markDone are
//       ONLY ever touched when `resume` is true (see bin/bh-fullscan.test.mjs
//       "resume: without --resume, no fullscan-state.json is ever written"),
//       so a state file can only exist after run 1 if run 1 itself passed
//       --resume -- this is the real, correct way an operator uses this
//       feature (turn resumability on from the start of a scan you might
//       need to interrupt), not an inaccuracy.
//
//   (b) Bounded retry: rather than faking a transient, this run passes
//       --max-retries 1 and relies on a REAL, deterministic transient that
//       already exists in the bh:base image: enum:nuclei's real binary
//       exits non-zero (not 2 -- so classified "transient", never "denied")
//       on every invocation here because bh:base ships no bundled nuclei
//       templates (see fullscan-e2e.test.mjs's own comment on this). That
//       makes nuclei's step the one unit of work that markDone() NEVER
//       records (only "ok"/"denied" outcomes are marked done -- see
//       runFullscan in src/orchestrate/fullscan.mjs), so it is a real
//       forced-transient available with zero mocking, confirmed by hand
//       against a live run before writing the assertions below.
//
//       This nuclei transient is PERMANENT per invocation (no bundled
//       templates never becomes "has templates" without rebuilding bh:base,
//       which the controller explicitly disallows here) -- so it cannot
//       demonstrate "fails once, then succeeds", only "the bounded-retry
//       loop really fires against a real transient and the run still
//       completes". That happy-path ("transient once, then ok, scan
//       completes") is already covered for real by two existing tests that
//       stub only the spawn boundary (not docker/the tools):
//         - src/orchestrate/fullscan.test.mjs:398 "runFullscan: retry --
//           transient retried up to maxRetries then ok..." (pure driver, O3)
//         - bin/bh-fullscan.test.mjs:489 "maxRetries: a transient (non-0,
//           non-2) exit is retried up to maxRetries with injected sleep
//           receiving backoff(attempt) delays, then succeeds" (CLI seam)
//       This e2e's retry assertions below only add what those two CANNOT:
//       proof that the real bounded-retry code path fires against a truly
//       real (uncontrolled, unmocked) tool transient inside a real
//       container, and that the whole staged pipeline still completes.
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync, execFileSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { stepKey, isDone } from "../src/orchestrate/run-state.mjs"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const bhFullscan = join(repoRoot, "bin", "bh-fullscan.mjs")
const dockerDir = join(repoRoot, "docker")

const PREFIX = "bh-e2eresil"
const RUN_ID = `${PREFIX}-${process.pid}`
const NET = `${RUN_ID}-net`
const TARGET = `${RUN_ID}-target`
const ENG_CONTAINER = RUN_ID
const ENG_NAME = ENG_CONTAINER.slice(3)
// See fullscan-e2e.test.mjs's own comment: httpx/ffuf only resolve the
// dotted "<name>.<network>" FQDN reliably in this image's tool versions.
const TARGET_FQDN = `${TARGET}.${NET}`

function dockerAvailable() {
  const r = spawnSync("docker", ["info"], { stdio: "ignore" })
  return r.status === 0
}
const available = dockerAvailable()

function rmContainer(name) {
  spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" })
}
function rmNetwork(name) {
  spawnSync("docker", ["network", "rm", name], { stdio: "ignore" })
}

function sweepContainersByPrefix(prefix) {
  const r = spawnSync("docker", ["ps", "-aq", "--filter", `name=${prefix}`], { encoding: "utf8" })
  const ids = r.stdout.trim().split("\n").filter(Boolean)
  for (const id of ids) spawnSync("docker", ["rm", "-f", id], { stdio: "ignore" })
}
function sweepNetworksByPrefix(prefix) {
  const r = spawnSync("docker", ["network", "ls", "-q", "--filter", `name=${prefix}`], { encoding: "utf8" })
  const ids = r.stdout.trim().split("\n").filter(Boolean)
  for (const id of ids) spawnSync("docker", ["network", "rm", id], { stdio: "ignore" })
}

// bh:base is already built by the controller before this suite runs -- this
// must be a no-op inspect here, never a real build.
function ensureImage(tag, buildOrPull) {
  const r = spawnSync("docker", ["image", "inspect", tag], { stdio: "ignore" })
  if (r.status !== 0) buildOrPull()
}

function waitForHttp(execContainer, url, { retries = 40, delayMs = 250 } = {}) {
  for (let i = 0; i < retries; i++) {
    const r = spawnSync("docker", ["exec", execContainer, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", url], {
      encoding: "utf8",
    })
    if (r.status === 0 && r.stdout.trim() === "200") return
    spawnSync("sleep", [String(delayMs / 1000)])
  }
  throw new Error(`target never became ready: ${url}`)
}

let dataDir

beforeAll(() => {
  if (!available) return

  sweepContainersByPrefix(PREFIX)
  sweepNetworksByPrefix(PREFIX)

  dataDir = mkdtempSync(join(tmpdir(), "boundhound-fullscan-resil-e2e-"))
  mkdirSync(join(dataDir, "engagements", ENG_NAME), { recursive: true })

  ensureImage("bh:base", () => execFileSync("docker", ["build", "-t", "bh:base", dockerDir], { stdio: "inherit" }))
  ensureImage("nginx:alpine", () => execFileSync("docker", ["pull", "nginx:alpine"], { stdio: "inherit" }))

  execFileSync("docker", ["network", "create", NET])
  execFileSync("docker", ["run", "-d", "--name", TARGET, "--network", NET, "nginx:alpine"])
  execFileSync("docker", ["run", "-d", "--name", ENG_CONTAINER, "--network", NET, "bh:base"])

  waitForHttp(ENG_CONTAINER, `http://${TARGET_FQDN}`)

  const scope = `engagement: ${ENG_NAME}
authorization: "lab test - local docker e2e, no external target (fullscan-resilience-e2e.test.mjs)"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["${TARGET_FQDN}"]
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: "fullscan-resilience-e2e.test.mjs scaffolded engagement"
`
  writeFileSync(join(dataDir, "engagements", ENG_NAME, "scope.yaml"), scope)
  writeFileSync(join(dataDir, "engagements", ".active"), ENG_NAME)
}, 90000)

afterAll(() => {
  if (!available) return
  rmContainer(ENG_CONTAINER)
  rmContainer(TARGET)
  rmNetwork(NET)
  if (dataDir) rmSync(dataDir, { recursive: true, force: true })
}, 30000)

test.skipIf(!available)(
  "fullscan resilience e2e (requires docker): real --resume skips already-done steps on a second real run; real --max-retries fires against a genuine transient",
  () => {
    const outputDir = join(dataDir, "engagements", ENG_NAME, "output")
    const statePath = join(outputDir, "fullscan-state.json")
    const reportPath = join(outputDir, "report", "report.md")
    const auditPath = join(dataDir, "engagements", ENG_NAME, "audit.log")

    // The four steps expected to succeed ("ok") against this live nginx
    // target and therefore get markDone()'d after run 1 -- confirmed by hand
    // against a live run before writing this test (see task-5-report.md).
    // enum:nuclei is deliberately excluded: bh:base ships no bundled nuclei
    // templates, so its real binary exits non-zero (transient) on every
    // invocation here and is NEVER marked done -- see the file header.
    const nucleiTargetUrl = `http://${TARGET_FQDN}`
    const stableSteps = [
      { stage: "recon:subfinder", tool: "subfinder", target: TARGET_FQDN },
      { stage: "recon:httpx", tool: "httpx", target: `http://${TARGET_FQDN}` },
      { stage: "recon:nmap", tool: "nmap", target: TARGET_FQDN },
      { stage: "enum:ffuf", tool: "ffuf", target: `${nucleiTargetUrl}/FUZZ` },
    ]

    // --- RUN 1: real `node bin/bh-fullscan.mjs --resume --max-retries 1` ---
    // --max-retries 1 is passed on BOTH runs so the real bounded-retry loop
    // engages against nuclei's real transient on every invocation (see file
    // header for why this can't demonstrate "eventually succeeds" for real,
    // and where that happy path IS covered for real).
    const run1 = spawnSync(
      "node",
      [bhFullscan, "--data-dir", dataDir, "--no-exploit", "--resume", "--max-retries", "1"],
      { encoding: "utf8" }
    )
    expect(run1.status).toBe(0)
    expect(run1.stderr).toContain("fullscan complete")

    // Real bounded-retry evidence: the exact log line runFullscan (src/
    // orchestrate/fullscan.mjs) emits when a transient outcome is retried,
    // built from the real nuclei target url -- proves the retry loop really
    // fired against a real transient, not just that the run completed.
    const retryLine = `stage enum:nuclei: step nuclei ${nucleiTargetUrl} transient (attempt 1/1), retrying:`
    expect(run1.stderr).toContain(retryLine)

    // --- 1. real fullscan-state.json: exists, versioned, has done units ---
    expect(existsSync(statePath)).toBe(true)
    const state1 = JSON.parse(readFileSync(statePath, "utf8"))
    expect(state1.version).toBe(1)
    for (const step of stableSteps) {
      expect(isDone(state1, stepKey(step))).toBe(true)
    }
    // nuclei's real transient never settles to "ok"/"denied" in this image,
    // so it must NOT be recorded done -- if it were, that would mean the
    // driver started marking transient outcomes done, a correctness
    // regression this test exists in part to catch.
    expect(isDone(state1, stepKey({ stage: "enum:nuclei", tool: "nuclei", target: nucleiTargetUrl }))).toBe(false)
    const doneKeys1 = Object.keys(state1.done).sort()
    expect(doneKeys1.length).toBe(stableSteps.length)

    // --- 2. real report.md: produced, covers the target ---
    expect(existsSync(reportPath)).toBe(true)
    const report1 = readFileSync(reportPath, "utf8")
    expect(report1).toContain(`# Penetration Test Report — ${ENG_NAME}`)
    expect(report1).toContain(TARGET_FQDN)
    expect(report1).toContain("http-service")
    expect(report1).toContain("open-port")

    // --- 3. real audit.log: in-scope ALLOWs, zero DENY / out-of-scope contact ---
    expect(existsSync(auditPath)).toBe(true)
    const rawAudit1 = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean)
    const auditCount1 = rawAudit1.length
    const auditEntries1 = rawAudit1.map((l) => JSON.parse(l))
    expect(auditEntries1.length).toBeGreaterThan(0)
    expect(auditEntries1.every((e) => e.decision === "ALLOW")).toBe(true)
    expect(auditEntries1.every((e) => typeof e.target === "string" && e.target.includes(TARGET_FQDN))).toBe(true)
    for (const step of stableSteps) {
      expect(auditEntries1.some((e) => e.tool === step.tool && e.target === step.target)).toBe(true)
    }

    // --- RUN 2: real re-run with --resume --max-retries 1 -----------------
    const run2 = spawnSync(
      "node",
      [bhFullscan, "--data-dir", dataDir, "--no-exploit", "--resume", "--max-retries", "1"],
      { encoding: "utf8" }
    )
    expect(run2.status).toBe(0)
    expect(run2.stderr).toContain("fullscan complete")

    // --- (a) THE CORE PROOF: run 2 really skipped the already-done steps --
    // Direct evidence #1: the exact "resume: skip <key>" log line the
    // driver emits ONLY when isDone(state, key) is true (src/orchestrate/
    // fullscan.mjs) appears for every one of the 4 stable steps.
    for (const step of stableSteps) {
      expect(run2.stderr).toContain(`resume: skip ${stepKey(step)}`)
    }
    // Direct evidence #2: none of the runner's own "ran and wrote output"
    // log lines (makeRunner in bin/bh-fullscan.mjs: `stage X: tool target ->
    // path`) appear for the stable steps in run 2 -- structurally impossible
    // if resume:skip fired (the runner is never even called), asserted
    // directly anyway as a second, independent real signal.
    for (const step of stableSteps) {
      expect(run2.stderr).not.toContain(`stage ${step.stage}: ${step.tool} ${step.target} ->`)
    }
    // Direct evidence #3: nuclei's own real transient DID fire again in run
    // 2 (it is still not done, by design) -- proves run 2 is not simply
    // short-circuiting the whole scan, only the already-done steps.
    expect(run2.stderr).toContain(retryLine)

    // --- state file after run 2: unchanged (no already-done step lost or
    // altered; nuclei still never settles) ---
    const state2 = JSON.parse(readFileSync(statePath, "utf8"))
    expect(Object.keys(state2.done).sort()).toEqual(doneKeys1)

    // --- audit.log delta: run 2 added zero new ALLOW entries for any of the
    // 4 already-done (tool,target) pairs -- the most robust real signal
    // available, independent of the log-line assertions above ---
    const rawAudit2 = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean)
    expect(rawAudit2.length).toBeGreaterThan(auditCount1) // nuclei's real retry did add entries
    const delta = rawAudit2.slice(auditCount1).map((l) => JSON.parse(l))
    expect(delta.length).toBeGreaterThan(0)
    expect(delta.every((e) => e.decision === "ALLOW")).toBe(true)
    for (const step of stableSteps) {
      expect(delta.some((e) => e.tool === step.tool && e.target === step.target)).toBe(false)
    }
    // Every delta entry is accounted for by nuclei's real, permanent,
    // per-invocation transient (2 attempts: maxRetries:1 -> up to 2 real
    // bh-exec spawns, both ALLOW, both targeting the same real url).
    expect(delta.every((e) => e.tool === "nuclei" && e.target === nucleiTargetUrl)).toBe(true)

    // --- report.md after run 2: still real, still valid, still covers the
    // target (findings/report synth always re-runs regardless of resume) ---
    expect(existsSync(reportPath)).toBe(true)
    const report2 = readFileSync(reportPath, "utf8")
    expect(report2).toContain(`# Penetration Test Report — ${ENG_NAME}`)
    expect(report2).toContain(TARGET_FQDN)
  },
  240000,
)
