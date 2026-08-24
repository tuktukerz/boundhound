// test/enum-e2e.test.mjs
//
// REAL end-to-end test for Phase 2 enum (spec §8, E2E row). No mocking of
// docker, the tools, or the CLI subprocesses: this spins up an actual local
// target container (nginx on :80) on an actual docker network, runs the
// actual bh:base image as the engagement container on that same network,
// and drives the real bin/bh-exec.mjs / bin/bh-enum-map.mjs CLIs as real
// child processes -- exactly as an operator would -- to prove the whole
// enum pipeline (scope-check -> safety-check -> catalog -> command-builder
// -> docker exec -> real ffuf/nuclei -> enum-map merge) end to end.
//
// Deterministic + offline: everything happens against containers on a
// docker-internal bridge network (container-name DNS resolves via Docker's
// embedded resolver at 127.0.0.11, no external DNS/network needed once the
// images are locally cached); nuclei is pointed at a bundled custom
// template (test/fixtures/enum/nginx-detect.yaml) instead of its normal
// online template repo, so no real-world host or network is ever touched.
//
// Mirrors test/recon-e2e.test.mjs's structure (docker-availability guard,
// unique per-pid names with a prefix-sweep preemptive cleanup, fail-safe
// afterAll teardown, the dotted-FQDN target trick) -- see that file's
// comments for the rationale behind each of those mechanisms, not repeated
// here.
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync, execFileSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { parseFfufJson } from "../src/enum/enum-map.mjs"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const bhExec = join(repoRoot, "bin", "bh-exec.mjs")
const bhEnumMap = join(repoRoot, "bin", "bh-enum-map.mjs")
const dockerDir = join(repoRoot, "docker")
const nucleiTemplate = join(repoRoot, "test", "fixtures", "enum", "nginx-detect.yaml")

// Fixed prefix + this process's pid: unique per run, same rationale as
// recon-e2e.test.mjs -- but its own prefix, so a boundhound-recon-e2e-*
// suite running concurrently on the same daemon never collides with (or
// gets swept by) this one.
const PREFIX = "bh-e2eenum"
const RUN_ID = `${PREFIX}-${process.pid}` // e.g. "bh-e2eenum-12345"
const NET = `${RUN_ID}-net`
const TARGET = `${RUN_ID}-target`
const ENG_CONTAINER = RUN_ID // docker container name, must be "bh-<engagement-name>"
const ENG_NAME = ENG_CONTAINER.slice(3) // engagement name bh-exec.mjs resolves back into "bh-<name>"
// httpx/ffuf (Go binaries with their own DNS resolution path) only resolve
// the dotted "<name>.<network>" FQDN reliably in this image's tool
// versions -- verified by hand in recon-e2e.test.mjs. Using the dotted FQDN
// for --target keeps one target string that works for curl (readiness
// poll), ffuf, and nuclei alike.
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
// RUN_ID/NET/TARGET -- but they do share the "bh-e2eenum" prefix.
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

// Poll real readiness instead of guessing a fixed sleep: ffuf/nuclei must
// only run once nginx inside the target container is actually accepting
// connections. Polls through the engagement container via curl (already in
// bh:base) -- the same network path the real ffuf/nuclei runs will use.
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

  dataDir = mkdtempSync(join(tmpdir(), "boundhound-enum-e2e-"))
  mkdirSync(join(dataDir, "engagements", ENG_NAME, "output", "enum"), { recursive: true })

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
authorization: "lab test - local docker e2e, no external target (enum-e2e.test.mjs)"
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
notes: "enum-e2e.test.mjs scaffolded engagement"
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
  "enum e2e (requires docker): real ffuf + nuclei vs a local target container merge into enum-map.json",
  () => {
    const enumDir = join(dataDir, "engagements", ENG_NAME, "output", "enum")

    // 1. Real ffuf through the real bh-exec CLI: scope-checked, audited,
    // running inside the engagement container against the target FQDN.
    //
    // ffuf's "-of json" only switches the *format* of the file writer; it
    // does not by itself redirect JSON to stdout -- verified by hand: with
    // "-s" (silent) alone and no "-o", real stdout carries only the bare
    // matched keyword ("index.html"), never the JSON blob, regardless of
    // -of. The fix (this is the documented flow -- see pentest-enum/SKILL.md
    // Step 1): "-o /dev/stdout" names a real output file that happens to be
    // the process's own stdout, so ffuf's JSON writer fires and the blob
    // lands on stdout for real. docker exec runs with stdio:"inherit" (see
    // bin/bh-exec.mjs's dockerExec), so that stdout passes straight through
    // to this spawnSync's own captured stdout -- same mechanism the nuclei
    // run below already relies on, no docker cp needed.
    const ffufRun = spawnSync(
      "node",
      [
        bhExec,
        "ffuf",
        "--target",
        `http://${TARGET_FQDN}/FUZZ`,
        "--data-dir",
        dataDir,
        "--",
        "-w",
        "/usr/share/boundhound/wordlists/common.txt",
        "-mc",
        "200",
        "-t",
        "20",
        "-o",
        "/dev/stdout",
        "-of",
        "json",
        "-s",
      ],
      { encoding: "utf8" },
    )
    expect(ffufRun.status).toBe(0)

    // Written to disk exactly as the documented `>` redirect would capture
    // it -- raw, undoctored stdout. ffuf still emits a bare per-match
    // progress line on this same stdout ahead of the JSON blob even with
    // `-s` (verified by hand), so the file is not always byte-for-byte pure
    // JSON; that's real ffuf behavior, not a test artifact, so it's kept as
    // stdout writes it rather than hand-cleaned here.
    const ffufOutPath = join(enumDir, `ffuf-${TARGET}.json`)
    writeFileSync(ffufOutPath, ffufRun.stdout)

    // Read back through the real parser bh-enum-map itself uses --
    // parseFfufJson recovers the JSON object from the first `{` it finds,
    // tolerating exactly the leading noise described above (see its
    // dedicated unit tests in src/enum/enum-map.test.mjs).
    const ffufContent = parseFfufJson(readFileSync(ffufOutPath, "utf8"))
    const indexResult = ffufContent.find((r) => r.path === "index.html")
    expect(indexResult).toBeTruthy()
    expect(indexResult.status).toBe(200)

    // 2. Real nuclei through the same CLI, same scope check, same target,
    // matched against the bundled offline template copied in above. Unlike
    // ffuf, nuclei's "-jsonl" genuinely writes pure JSON-lines to stdout
    // (its banner/INF/ERR log lines all go to stderr) -- verified by hand
    // -- so this one really is captured straight off the audited run's
    // stdout, no docker cp needed.
    const nucleiRun = spawnSync(
      "node",
      [
        bhExec,
        "nuclei",
        "--target",
        `http://${TARGET_FQDN}`,
        "--data-dir",
        dataDir,
        "--",
        "-t",
        "/tmp/nginx-detect.yaml",
        "-jsonl",
        "-disable-update-check",
        "-c",
        "10",
        "-rl",
        "50",
      ],
      { encoding: "utf8" },
    )
    expect(nucleiRun.status).toBe(0)
    expect(nucleiRun.stdout).toContain('"template-id":"nginx-detect"')
    writeFileSync(join(enumDir, `nuclei-${TARGET}.jsonl`), nucleiRun.stdout)

    // 3. Real bh-enum-map merges both raw outputs into enum-map.json.
    const mapRun = spawnSync("node", [bhEnumMap, "--data-dir", dataDir], { encoding: "utf8" })
    expect(mapRun.status).toBe(0)

    const map = JSON.parse(readFileSync(join(enumDir, "enum-map.json"), "utf8"))
    expect(Array.isArray(map.content)).toBe(true)
    expect(Array.isArray(map.findings)).toBe(true)

    const contentHit = map.content.find((c) => c.path === "index.html" && c.status === 200)
    expect(contentHit).toBeTruthy()
    expect(contentHit.host).toBe(TARGET_FQDN)

    const findingHit = map.findings.find((f) => f.template_id === "nginx-detect")
    expect(findingHit).toBeTruthy()
    expect(findingHit.severity).toBe("info")
    expect(findingHit.host).toBe(TARGET_FQDN)

    expect(map.by_severity.info).toBeGreaterThanOrEqual(1)
  },
  60000,
)

// Asserting "the audit log's LAST line is our DENY" relies on this test
// running after the main pipeline test above in file order (bun runs tests
// within one file sequentially, in declaration order) -- the pipeline test
// appends its own ALLOW entries first (ffuf, then nuclei), then this test
// appends the one DENY entry checked below, so it is genuinely the last
// line by the time this runs.
test.skipIf(!available)("enum e2e (requires docker): out-of-scope target is DENYed (exit 2) and audited", () => {
  const auditPath = join(dataDir, "engagements", ENG_NAME, "audit.log")

  const r = spawnSync(
    "node",
    [
      bhExec,
      "ffuf",
      "--target",
      "http://10.99.99.99/FUZZ",
      "--data-dir",
      dataDir,
      "--",
      "-w",
      "/usr/share/boundhound/wordlists/common.txt",
      "-mc",
      "200",
    ],
    { encoding: "utf8" },
  )
  expect(r.status).toBe(2)
  expect(r.stderr).toMatch(/^DENY /)

  const lines = readFileSync(auditPath, "utf8").trim().split("\n")
  const last = JSON.parse(lines[lines.length - 1])
  expect(last.decision).toBe("DENY")
  expect(last.target).toBe("http://10.99.99.99/FUZZ")
  expect(last.tool).toBe("ffuf")
})
