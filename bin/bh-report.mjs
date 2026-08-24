// bin/bh-report.mjs
//
// Thin CLI: reads the active engagement's verified findings.json + its
// scope.yaml (for report metadata) + best-effort summarizes audit.log, and
// writes a rendered markdown pentest report. Not a network tool — it only
// reads files already produced by earlier phases and renders them via the
// pure buildReport renderer (src/report/report.mjs), so it runs as plain
// `node bin/bh-report.mjs` (no docker exec involved).
import { join } from "node:path"
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { activeName, loadActiveConfig } from "../src/scope/active-engagement.mjs"
import { buildReport } from "../src/report/report.mjs"
import { dataRoot } from "../src/paths.mjs"

// findings.json is Phase 4's output (spec §3): missing (verify hasn't run
// yet) or invalid JSON (a half-written file, garbage) both mean "nothing to
// report yet" -> empty findings, which buildReport already renders as a
// valid "no findings" report rather than throwing.
function readFindingsOrEmpty(path) {
  if (!existsSync(path)) return []
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"))
    return Array.isArray(parsed?.findings) ? parsed.findings : []
  } catch {
    return []
  }
}

// Best-effort ALLOW/DENY tally over the engagement's audit.log (spec §3):
// each line is one appendAudit()-written JSON object, and its `decision`
// field is always the literal string "ALLOW" or "DENY" (src/audit/audit-log.mjs),
// so a plain substring test avoids parsing every line as JSON just to read
// one field. Missing/unreadable log -> undefined, which buildReport's
// appendix already treats as "omit this line" rather than throwing.
function summarizeAudit(path) {
  if (!existsSync(path)) return undefined
  try {
    const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0)
    let allow = 0
    let deny = 0
    for (const line of lines) {
      if (line.includes('"decision":"ALLOW"')) allow++
      else if (line.includes('"decision":"DENY"')) deny++
    }
    return { allow, deny, total: lines.length }
  } catch {
    return undefined
  }
}

export function runReport({ dataDir, now } = {}) {
  const dDir = dataDir ?? dataRoot()
  const name = activeName(dDir)
  if (!name) return { code: 3, message: "fail-closed: no active engagement" }

  // loadActiveConfig re-reads scope.yaml through parseScope, which throws on
  // a missing file or any rule violation (missing engagement/authorization,
  // invalid scope_enforcement, bad CIDR, TLD-level wildcard, ...). A report
  // for a broken engagement is refused, consistent with the rest of the
  // system's deny-by-default posture (spec §3) -- fail-closed, no report
  // written.
  let meta
  try {
    meta = loadActiveConfig(dDir)
  } catch (e) {
    return { code: 3, message: `fail-closed: broken scope (${e.message})` }
  }

  const outputDir = join(dDir, "engagements", name, "output")
  const findings = readFindingsOrEmpty(join(outputDir, "verify", "findings.json"))
  const auditSummary = summarizeAudit(join(dDir, "engagements", name, "audit.log"))

  const markdown = buildReport({ findings, meta, auditSummary }, { now })

  // report.md is written into output/report/, mirroring bh-findings.mjs's
  // output/verify/ convention. mkdir -p defensively: an engagement that
  // hasn't run any earlier phase yet won't have output/report/ on disk.
  const reportDir = join(outputDir, "report")
  mkdirSync(reportDir, { recursive: true })
  const outPath = join(reportDir, "report.md")
  writeFileSync(outPath, markdown)

  return { code: 0, message: `wrote ${outPath}`, path: outPath }
}

// Optional "--data-dir <path>" pair, same convention/rationale as
// bh-exec.mjs / bh-engagement.mjs / bh-enum-map.mjs / bh-recon-map.mjs /
// bh-exploit-map.mjs / bh-findings.mjs: plugin-mode agent invocations pass
// the data dir explicitly since ${CLAUDE_PLUGIN_DATA} isn't exported to the
// agent's Bash tool session.
function extractDataDir(argv) {
  const i = argv.indexOf("--data-dir")
  if (i < 0) return { dataDir: null, rest: argv }
  const dataDir = argv[i + 1]
  return { dataDir, rest: [...argv.slice(0, i), ...argv.slice(i + 2)] }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here -- same argv-identity idiom as
// bh-exec.mjs / bh-engagement.mjs / bh-enum-map.mjs / bh-recon-map.mjs /
// bh-exploit-map.mjs / bh-findings.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir } = extractDataDir(process.argv.slice(2))
  const r = runReport(dataDir ? { dataDir } : {})
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
