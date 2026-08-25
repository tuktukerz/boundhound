// test/fullscan-e2e.test.mjs
//
// REAL end-to-end test for Phase 6's orchestrator (spec §6, E2E row). No
// mocking of docker, the tools, the bh-exec/bh-fullscan CLIs, or the
// synth (bh-*-map/bh-findings/bh-report) CLIs: this spins up an actual local
// target container (nginx on :80) on an actual docker network, runs the
// actual bh:base image as the engagement container on that same network,
// and drives the real `node bin/bh-fullscan.mjs --data-dir <tmp> --no-exploit`
// CLI exactly as an operator (or the autonomous agent) would -- proving the
// whole staged pipeline (scope-check -> recon:subfinder/httpx/nmap ->
// enum:nuclei/ffuf -> findings -> report) end to end against a live target,
// with every tool step still going through the same enforced bh-exec choke
// point (scope-check -> safety-check -> catalog -> command-builder -> docker
// exec).
//
// Mirrors test/enum-e2e.test.mjs / test/recon-e2e.test.mjs's structure
// (docker-availability guard, unique per-pid names with a prefix-sweep
// preemptive cleanup, fail-safe afterAll teardown, the dotted-FQDN target
// trick) -- see those files' comments for the rationale behind each
// mechanism, not repeated here. Own prefix ("bh-e2efullscan") so a
// recon-e2e/enum-e2e/exploit-e2e suite running concurrently on the same
// daemon never collides with (or gets swept by) this one.
//
// --no-exploit is passed deliberately (spec §3): it disables the
// exploit:sqlmap stage, keeping this run non-intrusive/offline-safe (nginx
// has no SQLi anyway, so sqlmap would only ever find nothing) and shaving a
// real sequential tool invocation off an already-multi-tool run.
//
// subfinder needs live internet access (it queries real passive-DNS/CT-log
// sources) to do anything useful, and this target is a fabricated
// docker-network FQDN with no real DNS presence, so recon:subfinder itself
// necessarily finds zero subdomains here. That is NOT worked around by
// mocking or skipping the stage -- targetsForStage (src/orchestrate/fullscan.mjs)
// is fixed, unmodified production code, so the real fullscan run really does
// invoke real subfinder first, through the real bh-exec choke point, exactly
// as it would for any other target. What make recon still succeed without
// live subdomain discovery is that recon:httpx/recon:nmap's target list
// (discoveredInScopeHosts) already includes every in-scope ROOT domain
// unconditionally, not just subfinder's discoveries -- so seeding the
// target host directly as an in-scope domain (rather than only relying on
// subfinder to discover it) is what lets the rest of the chain proceed. See
// docs/plans/2026-08-25-fase-6-orchestrator.md's task-4 note for the same
// reasoning.
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync, execFileSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const bhFullscan = join(repoRoot, "bin", "bh-fullscan.mjs")
const dockerDir = join(repoRoot, "docker")

const PREFIX = "bh-e2efullscan"
const RUN_ID = `${PREFIX}-${process.pid}` // e.g. "bh-e2efullscan-12345"
const NET = `${RUN_ID}-net`
const TARGET = `${RUN_ID}-target`
const ENG_CONTAINER = RUN_ID // docker container name, must be "bh-<engagement-name>"
const ENG_NAME = ENG_CONTAINER.slice(3) // engagement name bh-exec.mjs/bh-fullscan.mjs resolve back into "bh-<name>"
// httpx/ffuf (Go binaries with their own DNS resolution path) only resolve
// the dotted "<name>.<network>" FQDN reliably in this image's tool
// versions -- verified by hand in recon-e2e.test.mjs/enum-e2e.test.mjs.
// Using the dotted FQDN for the seeded in-scope domain keeps one target
// string that resolves correctly for every real tool the fullscan chain
// invokes (subfinder, httpx, nmap, nuclei, ffuf).
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
// RUN_ID/NET/TARGET -- but they do share the "bh-e2efullscan" prefix.
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

// Poll real readiness instead of guessing a fixed sleep: the fullscan run's
// httpx/nmap/nuclei/ffuf steps must only run once nginx inside the target
// container is actually accepting connections. Polls through the engagement
// container via curl (already in bh:base) -- the same network path the real
// tool runs will use.
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

  dataDir = mkdtempSync(join(tmpdir(), "boundhound-fullscan-e2e-"))
  mkdirSync(join(dataDir, "engagements", ENG_NAME), { recursive: true })

  ensureImage("bh:base", () => execFileSync("docker", ["build", "-t", "bh:base", dockerDir], { stdio: "inherit" }))
  ensureImage("nginx:alpine", () => execFileSync("docker", ["pull", "nginx:alpine"], { stdio: "inherit" }))

  execFileSync("docker", ["network", "create", NET])
  execFileSync("docker", ["run", "-d", "--name", TARGET, "--network", NET, "nginx:alpine"])
  execFileSync("docker", ["run", "-d", "--name", ENG_CONTAINER, "--network", NET, "bh:base"])

  waitForHttp(ENG_CONTAINER, `http://${TARGET_FQDN}`)

  // Engagement whose in_scope covers exactly the target FQDN -- strict
  // enforcement, deny-by-default for everything else. Seeded directly as a
  // literal in-scope domain (not "*."-prefixed) so it is its own "root
  // domain" for the orchestrator's planner (rootDomains() in
  // src/orchestrate/fullscan.mjs strips a "*." prefix but otherwise treats a
  // literal entry as its own root) -- recon:httpx/recon:nmap target every
  // in-scope root unconditionally, independent of whether recon:subfinder
  // (which runs first, and for real) discovered anything.
  const scope = `engagement: ${ENG_NAME}
authorization: "lab test - local docker e2e, no external target (fullscan-e2e.test.mjs)"
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
notes: "fullscan-e2e.test.mjs scaffolded engagement"
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
  "fullscan e2e (requires docker): real bh-fullscan autonomous scan (recon+enum, no-exploit) vs a live target container",
  () => {
    const outputDir = join(dataDir, "engagements", ENG_NAME, "output")

    // The one real, un-mocked entry point under test: every recon/enum tool
    // step below runs as a real `node bin/bh-exec.mjs <tool> ...` child
    // process of this CLI, each going through the real scope-check ->
    // safety-check -> catalog -> command-builder -> `docker exec` chain,
    // exactly as bin/bh-fullscan.mjs's own doc comment describes. Generous
    // timeout: this sequences real subfinder (needs its own passive-source
    // network round trips even though this target yields zero results),
    // real httpx, real nmap (5-port scan), real nuclei (exits fast: this
    // image ships no bundled templates, so this step is expected to fail
    // closed with a non-zero tool exit -- see below), and real ffuf against
    // the bundled wordlist -- five sequential real tool invocations plus
    // seven synth CLI invocations (recon-map x3, enum-map x2, findings,
        // report).
    const run = spawnSync("node", [bhFullscan, "--data-dir", dataDir, "--no-exploit"], { encoding: "utf8" })

    // exit 0 = runFullscan completed the staged pipeline. A per-step DENY or
    // a per-tool non-zero exit (see the nuclei note above) is logged and
    // skipped internally (spec §2.3) -- it is NOT surfaced as a non-zero
    // CLI exit, so an all-tools-succeeded assumption is not what this
    // asserts; only "the driver ran to completion and rendered a report".
    expect(run.status).toBe(0)
    expect(run.stderr).toContain("fullscan complete")

    // --- 1. real recon-map.json: nginx http-service + an open nmap port ---
    const reconMapPath = join(outputDir, "recon", "recon-map.json")
    expect(existsSync(reconMapPath)).toBe(true)
    const reconMap = JSON.parse(readFileSync(reconMapPath, "utf8"))

    expect(Array.isArray(reconMap.http_services)).toBe(true)
    const httpService = reconMap.http_services.find((s) => s.status_code === 200)
    expect(httpService).toBeTruthy()
    expect(httpService.url).toContain(TARGET_FQDN)

    expect(Array.isArray(reconMap.hosts)).toBe(true)
    const scannedHost = reconMap.hosts.find((h) => h.ports.some((p) => p.port === 80 && p.state === "open"))
    expect(scannedHost).toBeTruthy()
    expect(scannedHost.ports.some((p) => p.proto === "tcp" && p.port === 80 && p.state === "open")).toBe(true)

    // --- 2. real report.md: produced, covers the target ---
    const reportPath = join(outputDir, "report", "report.md")
    expect(existsSync(reportPath)).toBe(true)
    const report = readFileSync(reportPath, "utf8")

    expect(report).toContain(`# Penetration Test Report — ${ENG_NAME}`)
    // Scope section always lists every in_scope domain verbatim (spec §2.1's
    // renderScope), independent of whether any finding fired -- the most
    // robust "covers the target" assertion available.
    expect(report).toContain(TARGET_FQDN)
    // The recon-map's http-service + open-port findings (built by
    // bh-findings.mjs from the very recon-map.json just asserted on above)
    // must have made it all the way through findings.json into the rendered
    // Findings section -- proof this is the SAME real target flowing
    // through the whole pipeline, not just present in the Scope header.
    expect(report).toContain("http-service")
    expect(report).toContain("open-port")

    // --- 3. real --no-exploit wiring: sqlmap never ran ---
    expect(existsSync(join(outputDir, "exploit"))).toBe(false)

    // --- 4. real audit.log: in-scope ALLOWs, zero DENYs / out-of-scope contact ---
    const auditPath = join(dataDir, "engagements", ENG_NAME, "audit.log")
    expect(existsSync(auditPath)).toBe(true)
    const auditLines = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean)
    expect(auditLines.length).toBeGreaterThan(0)

    const auditEntries = auditLines.map((l) => JSON.parse(l))
    // Every one of subfinder/httpx/nmap/nuclei/ffuf's steps target the same
    // seeded in-scope FQDN (as a bare host or as a URL/FUZZ path built off
    // it) -- so every decision must be ALLOW, and every target must resolve
    // back to that one seeded host, proving no out-of-scope contact was
    // ever attempted.
    expect(auditEntries.every((e) => e.decision === "ALLOW")).toBe(true)
    expect(auditEntries.every((e) => typeof e.target === "string" && e.target.includes(TARGET_FQDN))).toBe(true)
    expect(auditEntries.some((e) => e.tool === "subfinder")).toBe(true)
    expect(auditEntries.some((e) => e.tool === "httpx")).toBe(true)
    expect(auditEntries.some((e) => e.tool === "nmap")).toBe(true)
    expect(auditEntries.some((e) => e.tool === "ffuf")).toBe(true)
    // sqlmap must never appear -- --no-exploit disables exploit:sqlmap entirely.
    expect(auditEntries.every((e) => e.tool !== "sqlmap")).toBe(true)
  },
  240000,
)
