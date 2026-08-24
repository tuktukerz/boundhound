// test/recon-e2e.test.mjs
//
// REAL end-to-end test for Phase 1 recon (spec §8, E2E row). No mocking of
// docker, the tools, or the CLI subprocesses: this spins up an actual local
// target container (nginx on :80) on an actual docker network, runs the
// actual bh:base image as the engagement container on that same network,
// and drives the real bin/bh-exec.mjs / bin/bh-recon-map.mjs CLIs as real
// child processes -- exactly as an operator would -- to prove the whole
// recon pipeline (scope-check -> safety-check -> catalog -> command-builder
// -> docker exec -> real nmap/httpx -> recon-map merge) end to end.
//
// Deterministic + offline: everything happens against containers on a
// docker-internal bridge network (container-name DNS resolves via Docker's
// embedded resolver at 127.0.0.11, no external DNS/network needed once the
// images are locally cached); no real-world host is ever touched.
//
// Mirrors the docker-availability guard pattern of docker/bridge-smoke.test.mjs
// (test.skipIf + a clear "why skipped" test title) -- but here docker itself
// (not one pre-existing named container) is the precondition, since this
// test creates all of its own containers.
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync, execFileSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const bhExec = join(repoRoot, "bin", "bh-exec.mjs")
const bhReconMap = join(repoRoot, "bin", "bh-recon-map.mjs")
const dockerDir = join(repoRoot, "docker")

// Fixed prefix + this process's pid: unique per run (so two runs sharing a
// docker daemon never collide on `docker run --name` / `docker network
// create`), while the prefix stays predictable enough that a crashed prior
// run's leftovers (a different pid, but the same "bh-e2erecon" prefix) are
// still found and removed by the preemptive sweep in beforeAll -- see
// spec/task-8 brief step 7 ("use unique names... to avoid collisions",
// "don't let a mid-test failure leak containers"). This suite assumes it is
// the only in-flight "bh-e2erecon*" run against this docker daemon at a
// time -- the prefix sweep below is a crash-recovery mechanism, not a lock,
// so it is not safe against a genuinely concurrent bh-e2erecon run on a
// shared daemon; fine for local dev and per-job-isolated CI, where each test
// run owns the daemon (or its own pid namespace) exclusively.
const PREFIX = "bh-e2erecon"
const RUN_ID = `${PREFIX}-${process.pid}` // e.g. "bh-e2erecon-12345"
const NET = `${RUN_ID}-net`
const TARGET = `${RUN_ID}-target`
const ENG_CONTAINER = RUN_ID // docker container name, must be "bh-<engagement-name>"
const ENG_NAME = ENG_CONTAINER.slice(3) // engagement name bh-exec.mjs resolves back into "bh-<name>"
// Docker's embedded DNS resolves every container on a user-defined bridge
// network as both "<name>" and "<name>.<network>". httpx (a Go binary using
// its own DNS resolution path, not glibc) only resolves the dotted form
// reliably in this image's httpx version -- verified by hand: a bare
// single-label name ("bh-e2erecon-target") fails inside httpx with
// "unsupported protocol scheme", while nmap/curl (glibc resolver) succeed
// with either form. Using the dotted FQDN for --target keeps one target
// string that works for both tools.
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
// RUN_ID/NET/TARGET -- but they do share the "bh-e2erecon" prefix. Best
// effort: an empty `-q` list is a no-op `rm -f`/`network rm` with no args,
// which docker itself rejects harmlessly (stdio ignored either way).
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

// Ensure an image exists locally; only pull/build it if truly absent. For
// bh:base this mirrors bin/bh-container's own "inspect, build only if
// missing" logic (spec: the controller has already built bh:base, so this
// must be a no-op inspect here, never a real build).
function ensureImage(tag, buildOrPull) {
  const r = spawnSync("docker", ["image", "inspect", tag], { stdio: "ignore" })
  if (r.status !== 0) buildOrPull()
}

// Poll real readiness instead of guessing a fixed sleep: nmap/httpx must
// only run once nginx inside the target container is actually accepting
// connections. Polls through the engagement container via curl (already in
// bh:base) -- the same network path the real nmap/httpx runs will use.
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
  // containers/network. Swept by PREFIX (not this run's own exact names):
  // a crashed run had a different pid, so only the shared "bh-e2erecon"
  // prefix -- not RUN_ID/NET/TARGET -- can find its leftovers.
  sweepContainersByPrefix(PREFIX)
  sweepNetworksByPrefix(PREFIX)

  dataDir = mkdtempSync(join(tmpdir(), "boundhound-recon-e2e-"))
  mkdirSync(join(dataDir, "engagements", ENG_NAME, "output", "recon"), { recursive: true })

  ensureImage("bh:base", () => execFileSync("docker", ["build", "-t", "bh:base", dockerDir], { stdio: "inherit" }))
  ensureImage("nginx:alpine", () => execFileSync("docker", ["pull", "nginx:alpine"], { stdio: "inherit" }))

  execFileSync("docker", ["network", "create", NET])
  execFileSync("docker", ["run", "-d", "--name", TARGET, "--network", NET, "nginx:alpine"])
  execFileSync("docker", ["run", "-d", "--name", ENG_CONTAINER, "--network", NET, "bh:base"])

  waitForHttp(ENG_CONTAINER, `http://${TARGET_FQDN}`)

  // Engagement whose in_scope covers exactly the target FQDN -- strict
  // enforcement, deny-by-default for everything else (proven by the
  // out-of-scope test below).
  const scope = `engagement: ${ENG_NAME}
authorization: "lab test - local docker e2e, no external target (recon-e2e.test.mjs)"
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
notes: "recon-e2e.test.mjs scaffolded engagement"
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

test.skipIf(!available)(
  "recon e2e (requires docker): real nmap + httpx vs a local target container merge into recon-map.json",
  () => {
    const reconDir = join(dataDir, "engagements", ENG_NAME, "output", "recon")

    // 1. Real nmap through the real bh-exec CLI: scope-checked, audited,
    // running inside the engagement container against the target FQDN.
    const nmapRun = spawnSync(
      "node",
      [bhExec, "nmap", "--target", TARGET_FQDN, "--data-dir", dataDir, "--", "-sT", "-Pn", "-p", "80", "-oG", "-"],
      { encoding: "utf8" },
    )
    expect(nmapRun.status).toBe(0)
    expect(nmapRun.stdout).toMatch(/80\/open\/tcp/)
    writeFileSync(join(reconDir, `${TARGET}.gnmap`), nmapRun.stdout)

    // 2. Real httpx through the same CLI, same scope check, same target.
    const httpxRun = spawnSync(
      "node",
      [bhExec, "httpx", "--target", `http://${TARGET_FQDN}`, "--data-dir", dataDir, "--", "-silent", "-json"],
      { encoding: "utf8" },
    )
    expect(httpxRun.status).toBe(0)
    expect(httpxRun.stdout).toContain('"status_code":200')
    writeFileSync(join(reconDir, "httpx.jsonl"), httpxRun.stdout)

    // 3. Real bh-recon-map merges both raw outputs into recon-map.json.
    const mapRun = spawnSync("node", [bhReconMap, "--data-dir", dataDir], { encoding: "utf8" })
    expect(mapRun.status).toBe(0)

    const map = JSON.parse(readFileSync(join(reconDir, "recon-map.json"), "utf8"))
    expect(Array.isArray(map.hosts)).toBe(true)
    expect(Array.isArray(map.http_services)).toBe(true)

    const scannedHost = map.hosts.find((h) => h.ports.some((p) => p.port === 80 && p.state === "open"))
    expect(scannedHost).toBeTruthy()
    expect(scannedHost.ports.some((p) => p.proto === "tcp" && p.service === "http")).toBe(true)

    const httpService = map.http_services.find((s) => s.status_code === 200)
    expect(httpService).toBeTruthy()
    expect(httpService.url).toContain(TARGET_FQDN)

    // nmap and httpx both report the target through the same resolved IP
    // (the "host" field in both parsers) -- the merge is genuinely about the
    // same real target, not two unrelated fixtures.
    expect(httpService.host).toBe(scannedHost.host)
  },
  30000,
)

// Asserting "the audit log's LAST line is our DENY" relies on this test
// running after the main pipeline test above in file order (bun runs tests
// within one file sequentially, in declaration order) -- the pipeline test
// appends its own ALLOW entries first, then this test appends the one DENY
// entry checked below, so it is genuinely the last line by the time this
// runs.
test.skipIf(!available)("recon e2e (requires docker): out-of-scope target is DENYed (exit 2) and audited", () => {
  const auditPath = join(dataDir, "engagements", ENG_NAME, "audit.log")

  const r = spawnSync(
    "node",
    [bhExec, "nmap", "--target", "10.99.99.99", "--data-dir", dataDir, "--", "-sT", "-Pn", "-p", "80", "-oG", "-"],
    { encoding: "utf8" },
  )
  expect(r.status).toBe(2)
  expect(r.stderr).toMatch(/^DENY /)

  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const last = JSON.parse(lines[lines.length - 1])
  expect(last.decision).toBe("DENY")
  expect(last.target).toBe("10.99.99.99")
  expect(last.tool).toBe("nmap")
})
