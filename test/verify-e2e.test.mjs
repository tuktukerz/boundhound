// test/verify-e2e.test.mjs
//
// REAL end-to-end test for Phase 4 verify (spec §6, E2E row). No mocking of
// docker, the tools, or the CLI subprocesses: this spins up an actual local
// target container (nginx on :80) on an actual docker network, runs the
// actual bh:base image as the engagement container on that same network,
// and drives the real bin/bh-exec.mjs / bin/bh-enum-map.mjs /
// bin/bh-findings.mjs CLIs as real child processes -- exactly as an
// operator + the pentest-verify skill would -- to prove the whole
// re-verification pipeline (candidate finding from a real nuclei run ->
// findings.json verified:false -> a SECOND real nuclei re-fire against the
// SAME target -> findings.json verified:true) end to end.
//
// Deterministic + offline: everything happens against containers on a
// docker-internal bridge network (container-name DNS resolves via Docker's
// embedded resolver at 127.0.0.11, no external DNS/network needed once the
// images are locally cached); both nuclei runs are pointed at the bundled
// custom template already used by the enum e2e suite
// (test/fixtures/enum/nginx-detect.yaml) instead of its normal online
// template repo, so no real-world host or network is ever touched.
//
// KEY CORRECTNESS POINT (see task-4-brief.md): a nuclei finding's `target`
// in findings.json is set by src/verify/findings.mjs from the enum-map's
// `host` field, which is whatever nuclei itself reports as `host` in its
// JSONL output. For the re-verify to genuinely FLIP the finding, the
// re-check run's `host` must equal the original finding's `host`. Rather
// than hand-picking a host string and hoping it matches nuclei's own
// convention, BOTH the initial candidate-producing run and the re-check
// run are REAL nuclei invocations against the exact same --target string
// and template, so their `host` fields match by construction -- no
// assumption about nuclei's internal host-formatting is required.
//
// Mirrors test/enum-e2e.test.mjs's structure (docker-availability guard,
// unique per-pid names with a prefix-sweep preemptive cleanup, fail-safe
// afterAll teardown, the dotted-FQDN target trick, the bundled offline
// template) -- see that file's comments for the rationale behind each of
// those mechanisms, not repeated here. This suite's own prefix
// ("bh-e2everify") keeps it from colliding with (or being swept by) a
// concurrently-running enum-e2e/recon-e2e/exploit-e2e suite on the same
// docker daemon.
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync, execFileSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { parseNucleiJsonl } from "../src/enum/enum-map.mjs"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const bhExec = join(repoRoot, "bin", "bh-exec.mjs")
const bhEnumMap = join(repoRoot, "bin", "bh-enum-map.mjs")
const bhFindings = join(repoRoot, "bin", "bh-findings.mjs")
const dockerDir = join(repoRoot, "docker")
// Reused, not duplicated, per task-4-brief.md -- the enum phase's bundled
// offline template already does exactly what this suite needs (an
// nginx-only, no-OOB, no-online-fetch detection match).
const nucleiTemplate = join(repoRoot, "test", "fixtures", "enum", "nginx-detect.yaml")

// Fixed prefix + this process's pid: unique per run, same rationale as
// enum-e2e.test.mjs / recon-e2e.test.mjs -- but its own prefix, so a
// concurrently-running bh-e2e* suite on the same docker daemon never
// collides with (or gets swept by) this one.
const PREFIX = "bh-e2everify"
const RUN_ID = `${PREFIX}-${process.pid}` // e.g. "bh-e2everify-12345"
const NET = `${RUN_ID}-net`
const TARGET = `${RUN_ID}-target`
const ENG_CONTAINER = RUN_ID // docker container name, must be "bh-<engagement-name>"
const ENG_NAME = ENG_CONTAINER.slice(3) // engagement name bh-exec.mjs resolves back into "bh-<name>"
// httpx/ffuf/nuclei (Go binaries with their own DNS resolution path) only
// resolve the dotted "<name>.<network>" FQDN reliably in this image's tool
// versions -- verified by hand in recon-e2e.test.mjs/enum-e2e.test.mjs.
const TARGET_FQDN = `${TARGET}.${NET}`

function dockerAvailable() {
  const r = spawnSync("docker", ["info"], { stdio: "ignore" })
  return r.status === 0
}
const available = dockerAvailable()

// Best-effort teardown: swallow errors so a container/network that never got
// created (or already got removed) doesn't fail cleanup. Used both for
// preemptive cleanup of leftovers from a previous crashed run, and for the
// real afterAll teardown.
function rmContainer(name) {
  spawnSync("docker", ["rm", "-f", name], { stdio: "ignore" })
}
function rmNetwork(name) {
  spawnSync("docker", ["network", "rm", name], { stdio: "ignore" })
}

// Prefix sweep (not exact-name lookup): a crashed prior run used a different
// pid, so its leftover container/network names don't match this run's exact
// RUN_ID/NET/TARGET -- but they do share the "bh-e2everify" prefix.
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

// Ensure an image exists locally; only pull/build it if truly absent. bh:base
// is already built by the controller before this suite runs -- this must be
// a no-op inspect here, never a real build (host disk is tight).
function ensureImage(tag, buildOrPull) {
  const r = spawnSync("docker", ["image", "inspect", tag], { stdio: "ignore" })
  if (r.status !== 0) buildOrPull()
}

// Poll real readiness instead of guessing a fixed sleep: nuclei must only
// run once nginx inside the target container is actually accepting
// connections. Polls through the engagement container via curl (already in
// bh:base) -- the same network path the real nuclei runs will use.
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

  // Preemptive cleanup in case a prior run crashed mid-test and leaked
  // containers/network.
  sweepContainersByPrefix(PREFIX)
  sweepNetworksByPrefix(PREFIX)

  dataDir = mkdtempSync(join(tmpdir(), "boundhound-verify-e2e-"))
  mkdirSync(join(dataDir, "engagements", ENG_NAME, "output", "enum"), { recursive: true })
  mkdirSync(join(dataDir, "engagements", ENG_NAME, "output", "verify", "recheck"), { recursive: true })

  ensureImage("bh:base", () => execFileSync("docker", ["build", "-t", "bh:base", dockerDir], { stdio: "inherit" }))
  ensureImage("nginx:alpine", () => execFileSync("docker", ["pull", "nginx:alpine"], { stdio: "inherit" }))

  execFileSync("docker", ["network", "create", NET])
  execFileSync("docker", ["run", "-d", "--name", TARGET, "--network", NET, "nginx:alpine"])
  execFileSync("docker", ["run", "-d", "--name", ENG_CONTAINER, "--network", NET, "bh:base"])

  waitForHttp(ENG_CONTAINER, `http://${TARGET_FQDN}`)

  // The bundled nuclei template has to be reachable from *inside* the
  // engagement container (nuclei's -t is a path nuclei itself opens via
  // docker exec, not something bh-exec.mjs ships for us) -- docker cp it in
  // once, during setup, not as part of the audited tool invocation itself.
  execFileSync("docker", ["cp", nucleiTemplate, `${ENG_CONTAINER}:/tmp/nginx-detect.yaml`])

  // Engagement whose in_scope covers exactly the target FQDN -- strict
  // enforcement, deny-by-default for everything else (proven by the
  // out-of-scope test below).
  const scope = `engagement: ${ENG_NAME}
authorization: "lab test - local docker e2e, no external target (verify-e2e.test.mjs)"
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
notes: "verify-e2e.test.mjs scaffolded engagement"
`
  writeFileSync(join(dataDir, "engagements", ENG_NAME, "scope.yaml"), scope)
  writeFileSync(join(dataDir, "engagements", ".active"), ENG_NAME)
}, 60000)

afterAll(() => {
  if (!available) return
  rmContainer(ENG_CONTAINER)
  rmContainer(TARGET)
  rmNetwork(NET)
  if (dataDir) rmSync(dataDir, { recursive: true, force: true })
}, 30000)

// Shared nuclei extraArgs -- IDENTICAL flags for both the candidate-producing
// run and the re-check run, per spec §2.3/non-goal: re-verification re-runs
// the SAME bounded check, never a heavier one.
const NUCLEI_ARGS = ["-t", "/tmp/nginx-detect.yaml", "-jsonl", "-disable-update-check", "-c", "10", "-rl", "50"]

test.skipIf(!available)(
  "verify e2e (requires docker): real re-verification flips a nuclei finding to verified in findings.json",
  () => {
    const enumDir = join(dataDir, "engagements", ENG_NAME, "output", "enum")
    const recheckDir = join(dataDir, "engagements", ENG_NAME, "output", "verify", "recheck")
    const findingsPath = join(dataDir, "engagements", ENG_NAME, "output", "verify", "findings.json")

    // 1. Real nuclei run #1 through the real bh-exec CLI: scope-checked,
    // audited, running inside the engagement container against the target
    // FQDN, matched against the bundled offline template. nuclei's
    // "-jsonl" genuinely writes pure JSON-lines to stdout (banner/INF/ERR
    // log lines all go to stderr) -- verified by hand in enum-e2e.test.mjs
    // -- so this is captured straight off the audited run's own stdout.
    const firstRun = spawnSync(
      "node",
      [bhExec, "nuclei", "--target", `http://${TARGET_FQDN}`, "--data-dir", dataDir, "--", ...NUCLEI_ARGS],
      { encoding: "utf8" },
    )
    expect(firstRun.status).toBe(0)
    expect(firstRun.stdout).toContain('"template-id":"nginx-detect"')
    writeFileSync(join(enumDir, `nuclei-${TARGET}.jsonl`), firstRun.stdout)

    // 2. Real bh-enum-map merges the raw nuclei output into enum-map.json --
    // this is the candidate finding's source.
    const mapRun = spawnSync("node", [bhEnumMap, "--data-dir", dataDir], { encoding: "utf8" })
    expect(mapRun.status).toBe(0)

    // 3. Real bh-findings consolidates enum-map.json into findings.json.
    // With no recheck outputs yet, the nuclei finding must be present but
    // NOT verified.
    const findingsRun1 = spawnSync("node", [bhFindings, "--data-dir", dataDir], { encoding: "utf8" })
    expect(findingsRun1.status).toBe(0)

    const before = JSON.parse(readFileSync(findingsPath, "utf8"))
    const beforeFinding = before.findings.find(
      (f) => f.type === "nuclei" && f.evidence?.template_id === "nginx-detect"
    )
    expect(beforeFinding).toBeTruthy()
    expect(beforeFinding.verified).toBe(false)
    expect(beforeFinding.confidence).toBe("reported")

    // 4. Real nuclei run #2 -- the RE-VERIFY -- SAME target, SAME template,
    // SAME flags as run #1 (spec §2.3: re-verification never escalates).
    // Because it targets the identical --target string, nuclei reports the
    // identical `host` value, so it matches the original finding by
    // construction (see the KEY CORRECTNESS POINT comment at the top of
    // this file).
    const recheckRun = spawnSync(
      "node",
      [bhExec, "nuclei", "--target", `http://${TARGET_FQDN}`, "--data-dir", dataDir, "--", ...NUCLEI_ARGS],
      { encoding: "utf8" },
    )
    expect(recheckRun.status).toBe(0)
    expect(recheckRun.stdout).toContain('"template-id":"nginx-detect"')

    const recheckParsed = parseNucleiJsonl(recheckRun.stdout)
    const recheckHit = recheckParsed.find((f) => f.template_id === "nginx-detect")
    expect(recheckHit).toBeTruthy()
    // Sanity check backing the KEY CORRECTNESS POINT: the two real nuclei
    // runs against the same target genuinely produced the same `host`.
    expect(recheckHit.host).toBe(beforeFinding.target)

    writeFileSync(join(recheckDir, `${recheckHit.host}.jsonl`), recheckRun.stdout)

    // 5. Real bh-findings again -- folds the recheck output back in via
    // applyVerification. The SAME finding (same stable id) must now be
    // verified:true / confidence:"confirmed", never dropped or replaced.
    const findingsRun2 = spawnSync("node", [bhFindings, "--data-dir", dataDir], { encoding: "utf8" })
    expect(findingsRun2.status).toBe(0)

    const after = JSON.parse(readFileSync(findingsPath, "utf8"))
    const afterFinding = after.findings.find((f) => f.id === beforeFinding.id)
    expect(afterFinding).toBeTruthy()
    expect(afterFinding.verified).toBe(true)
    expect(afterFinding.confidence).toBe("confirmed")

    // Total finding count is unchanged by re-verification -- it flips a
    // flag on the existing finding, it never adds or removes one.
    expect(after.findings.length).toBe(before.findings.length)
  },
  120000,
)

// Asserting "the audit log's LAST line is our DENY" relies on this test
// running after the flip test above in file order (bun runs tests within
// one file sequentially, in declaration order) -- the flip test appends its
// own ALLOW entries first (two nuclei runs), then this test appends the one
// DENY entry checked below, so it is genuinely the last line by the time
// this runs.
test.skipIf(!available)("verify e2e (requires docker): out-of-scope re-check target is DENYed (exit 2) and audited", () => {
  const auditPath = join(dataDir, "engagements", ENG_NAME, "audit.log")

  const r = spawnSync(
    "node",
    [bhExec, "nuclei", "--target", "http://10.99.99.99", "--data-dir", dataDir, "--", ...NUCLEI_ARGS],
    { encoding: "utf8" },
  )
  expect(r.status).toBe(2)
  expect(r.stderr).toMatch(/^DENY /)

  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const last = JSON.parse(lines[lines.length - 1])
  expect(last.decision).toBe("DENY")
  expect(last.target).toBe("http://10.99.99.99")
  expect(last.tool).toBe("nuclei")
})
