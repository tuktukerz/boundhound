// test/report-e2e.test.mjs
//
// REAL end-to-end test for Phase 5 report (spec §6, E2E row). No mocking:
// this seeds a temp engagement's output/{recon,enum,exploit}/*-map.json
// files by feeding realistic raw-tool-output text through the REAL
// buildReconMap/buildEnumMap/buildExploitMap builders (src/recon/recon-map.mjs,
// src/enum/enum-map.mjs, src/exploit/exploit-map.mjs) -- so the seeded maps
// have the EXACT shape bin/bh-recon-map.mjs / bin/bh-enum-map.mjs /
// bin/bh-exploit-map.mjs would themselves have written -- then drives the
// real bin/bh-findings.mjs and bin/bh-report.mjs CLIs as real child
// processes, back to back, exactly as an operator would run them, to prove
// the whole chain (per-tool maps -> consolidated+verified findings.json ->
// rendered report.md) end to end.
//
// Offline + deterministic: reporting never touches a network or a
// container (spec §1) -- unlike test/{recon,enum,exploit,verify}-e2e.test.mjs
// this suite needs no docker at all, so it is plain `node bin/...`
// subprocesses over a temp --data-dir and always runs (no availability
// guard, no skipIf).
import { test, expect, beforeAll, afterAll } from "bun:test"
import { spawnSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { buildReconMap } from "../src/recon/recon-map.mjs"
import { buildEnumMap } from "../src/enum/enum-map.mjs"
import { buildExploitMap } from "../src/exploit/exploit-map.mjs"

const repoRoot = fileURLToPath(new URL("..", import.meta.url))
const bhFindings = join(repoRoot, "bin", "bh-findings.mjs")
const bhReport = join(repoRoot, "bin", "bh-report.mjs")

const now = () => "2026-08-25T00:00:00.000Z"

const ENG_NAME = "acme"
const AUTHORIZATION = "SOW-2026-0825 — signed engagement letter, Acme Corp (report-e2e.test.mjs)"

// One subdomain + one HTTP service + one open SSH port -- real
// subfinder/httpx JSONL lines and a real nmap -oG grepable block, fed
// through the REAL buildReconMap so recon-map.json has the exact shape
// bin/bh-recon-map.mjs itself would have written.
const SUBFINDER_JSONL = `{"host":"www.acme.io","input":"acme.io","source":"crtsh"}\n`
const HTTPX_JSONL = `{"url":"https://acme.io","host":"acme.io","status_code":200,"title":"Acme Home","tech":["nginx"]}\n`
const NMAP_GNMAP = `# Nmap 7.94 scan initiated Tue Aug 25 00:00:00 2026 as: nmap -sT -sV -Pn -T3 -oG - 203.0.113.10
Host: 203.0.113.10 (acme.io)\tStatus: Up
Host: 203.0.113.10 (acme.io)\tPorts: 22/open/tcp//ssh///\tIgnored State: closed (999)
# Nmap done at Tue Aug 25 00:00:01 2026 -- 1 IP address (1 host up) scanned in 1.00 seconds
`

// One medium-severity nuclei finding + one ffuf content hit -- a real
// nuclei -jsonl line and a real ffuf -of json blob, fed through the REAL
// buildEnumMap.
const NUCLEI_JSONL =
  `{"template-id":"exposed-config-file","template-path":"http/exposures/configs/exposed-config-file.yaml",` +
  `"info":{"name":"Exposed Configuration File","author":["boundhound"],"tags":["exposure","config"],"severity":"medium"},` +
  `"type":"http","host":"acme.io","matched-at":"https://acme.io/config.php","ip":"203.0.113.10","timestamp":"2026-08-25T00:00:05Z"}\n`
const FFUF_JSON = JSON.stringify({
  commandline: "ffuf -w /usr/share/boundhound/wordlists/common.txt -u https://acme.io/FUZZ -mc 200 -of json",
  time: "2026-08-25T00:00:00Z",
  results: [
    {
      input: { FUZZ: "backup.zip" },
      position: 1,
      status: 200,
      length: 512,
      words: 5,
      lines: 3,
      "content-type": "application/zip",
      redirectlocation: "",
      scraper: {},
      duration: 1000000,
      resultfile: "",
      url: "https://acme.io/backup.zip",
      host: "acme.io",
    },
  ],
  config: { wordlist: ["/usr/share/boundhound/wordlists/common.txt:FUZZ"], url: "https://acme.io/FUZZ" },
})

// One confirmed SQL injection -- the SAME real sqlmap stdout capture the
// exploit-map suites already use (test/fixtures/exploit/vulnerable.sqlmap.txt),
// fed through the REAL buildExploitMap.
const SQLI_TARGET = "https://acme.io/login?id=1"
const SQLMAP_OUTPUT = readFileSync(join(repoRoot, "test", "fixtures", "exploit", "vulnerable.sqlmap.txt"), "utf8")

let dataDir

beforeAll(() => {
  dataDir = mkdtempSync(join(tmpdir(), "boundhound-report-e2e-"))
  const engDir = join(dataDir, "engagements", ENG_NAME)
  const outputDir = join(engDir, "output")
  mkdirSync(join(outputDir, "recon"), { recursive: true })
  mkdirSync(join(outputDir, "enum"), { recursive: true })
  mkdirSync(join(outputDir, "exploit"), { recursive: true })

  writeFileSync(join(dataDir, "engagements", ".active"), ENG_NAME)

  const scope = `engagement: ${ENG_NAME}
authorization: "${AUTHORIZATION}"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["acme.io"]
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: "report-e2e.test.mjs scaffolded engagement"
`
  writeFileSync(join(engDir, "scope.yaml"), scope)

  const reconMap = buildReconMap(
    { subfinderJsonl: SUBFINDER_JSONL, httpxJsonl: HTTPX_JSONL, nmapGrepable: NMAP_GNMAP },
    { now }
  )
  writeFileSync(join(outputDir, "recon", "recon-map.json"), JSON.stringify(reconMap, null, 2))

  const enumMap = buildEnumMap({ ffufJson: FFUF_JSON, nucleiJsonl: NUCLEI_JSONL }, { now })
  writeFileSync(join(outputDir, "enum", "enum-map.json"), JSON.stringify(enumMap, null, 2))

  const exploitMap = buildExploitMap({ sqlmap: [{ target: SQLI_TARGET, output: SQLMAP_OUTPUT }] }, { now })
  writeFileSync(join(outputDir, "exploit", "exploit-map.json"), JSON.stringify(exploitMap, null, 2))
})

afterAll(() => {
  if (dataDir) rmSync(dataDir, { recursive: true, force: true })
})

test("report e2e: real bh-findings + real bh-report over seeded real-shaped maps produce a real report.md", () => {
  const outputDir = join(dataDir, "engagements", ENG_NAME, "output")

  // 1. Real bh-findings CLI subprocess: consolidates the three seeded maps
  // into findings.json.
  const findingsRun = spawnSync("node", [bhFindings, "--data-dir", dataDir], { encoding: "utf8" })
  expect(findingsRun.status).toBe(0)

  const findingsPath = join(outputDir, "verify", "findings.json")
  expect(existsSync(findingsPath)).toBe(true)
  const written = JSON.parse(readFileSync(findingsPath, "utf8"))

  // 6 findings total: 1 open-port + 1 http-service + 1 subdomain (recon) +
  // 1 nuclei + 1 content (enum) + 1 sqli (exploit).
  expect(written.findings).toHaveLength(6)

  const sqli = written.findings.find((f) => f.type === "sqli")
  expect(sqli).toBeTruthy()
  expect(sqli.target).toBe(SQLI_TARGET)
  expect(sqli.severity).toBe("high")
  expect(sqli.verified).toBe(true)

  const nuclei = written.findings.find((f) => f.type === "nuclei")
  expect(nuclei).toBeTruthy()
  expect(nuclei.severity).toBe("medium")
  expect(nuclei.target).toBe("acme.io")

  const openPort = written.findings.find((f) => f.type === "open-port")
  expect(openPort).toBeTruthy()
  expect(openPort.target).toBe("203.0.113.10")
  expect(openPort.severity).toBe("info")

  // 2. Real bh-report CLI subprocess: renders findings.json + scope.yaml
  // into report.md.
  const reportRun = spawnSync("node", [bhReport, "--data-dir", dataDir], { encoding: "utf8" })
  expect(reportRun.status).toBe(0)

  const reportPath = join(outputDir, "report", "report.md")
  expect(existsSync(reportPath)).toBe(true)
  const md = readFileSync(reportPath, "utf8")

  // --- engagement metadata + authorization ----------------------------
  expect(md).toContain(`# Penetration Test Report — ${ENG_NAME}`)
  expect(md).toContain(AUTHORIZATION)

  // --- executive summary: severity counts consistent with the seeded
  // findings (1 high [sqli], 1 medium [nuclei], 4 info [open-port,
  // http-service, subdomain, content]) ---------------------------------
  expect(md).toContain("| Critical | 0 |")
  expect(md).toContain("| High | 1 |")
  expect(md).toContain("| Medium | 1 |")
  expect(md).toContain("| Low | 0 |")
  expect(md).toContain("| Info | 4 |")
  expect(md).toContain("**Verified:** 1 of 6 finding(s) have been independently verified.")

  // --- a findings section for each present severity, none for the two
  // absent severities (critical/low) -----------------------------------
  expect(md).toContain("#### HIGH (1)")
  expect(md).toContain("#### MEDIUM (1)")
  expect(md).toContain("#### INFO (4)")
  expect(md).not.toContain("#### CRITICAL")
  expect(md).not.toContain("#### LOW")

  // --- each seeded finding's target appears ---------------------------
  expect(md).toContain(`### [HIGH] sqli — ${SQLI_TARGET}`)
  expect(md).toContain("### [MEDIUM] nuclei — acme.io")
  expect(md).toContain("### [INFO] open-port — 203.0.113.10")
  expect(md).toContain("### [INFO] http-service — https://acme.io")
  expect(md).toContain("### [INFO] subdomain — www.acme.io")
  expect(md).toContain("### [INFO] content — https://acme.io/backup.zip")

  // --- remediation guidance for EVERY finding type present in this report
  // (sqli, nuclei, open-port, http-service, subdomain, content) -- each
  // fragment below is a verbatim, distinctive substring of that type's
  // entry in src/report/report.mjs's REMEDIATION table -------------------
  expect(md).toContain("Use parameterized queries / prepared statements")
  expect(md).toContain("Review the flagged template's category and severity")
  expect(md).toContain("Confirm the service is intentionally exposed")
  expect(md).toContain("Review this exposed service for necessity and attack-surface awareness")
  expect(md).toContain("Confirm this subdomain is still in active use")
  expect(md).toContain("Review this discovered content for unintended exposure")
})

// Proves the fail-closed path in the real chain: a broken scope.yaml must
// never produce a report, even though findings.json (from bh-findings) is
// perfectly fine -- bh-report refuses before it ever reads findings.
test("report e2e: broken scope.yaml -> real bh-report fails closed (code 3), no report.md written", () => {
  const brokenDir = mkdtempSync(join(tmpdir(), "boundhound-report-e2e-broken-"))
  try {
    const engDir = join(brokenDir, "engagements", ENG_NAME)
    mkdirSync(engDir, { recursive: true })
    writeFileSync(join(brokenDir, "engagements", ".active"), ENG_NAME)
    // Missing "authorization:" -> parseScope's ScopeError("missing authorization").
    writeFileSync(
      join(engDir, "scope.yaml"),
      `engagement: ${ENG_NAME}
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: []
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
`
    )

    const r = spawnSync("node", [bhReport, "--data-dir", brokenDir], { encoding: "utf8" })
    expect(r.status).toBe(3)
    expect(r.stderr).toContain("fail-closed")
    expect(existsSync(join(engDir, "output", "report", "report.md"))).toBe(false)
  } finally {
    rmSync(brokenDir, { recursive: true, force: true })
  }
})
