// bin/omop-exec.mjs
import { join } from "node:path"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { loadActiveConfig, activeName } from "../src/scope/active-engagement.mjs"
import { matchTarget } from "../src/scope/scope-matcher.mjs"
import { checkSafety } from "../src/safety/safety-check.mjs"
import { loadCatalog, findTool } from "../src/catalog/catalog-loader.mjs"
import { buildCommand } from "../src/command-builder/command-builder.mjs"
import { appendAudit } from "../src/audit/audit-log.mjs"

// argv: [tool, "--target", <t>, "--", ...extraArgs]
function parse(argv) {
  const tool = argv[0]
  const ti = argv.indexOf("--target")
  const target = ti >= 0 ? argv[ti + 1] : null
  const dd = argv.indexOf("--")
  const extraArgs = dd >= 0 ? argv.slice(dd + 1) : []
  return { tool, target, extraArgs }
}

// spawnSync (not execFileSync) so a non-zero tool exit is reported as a status
// code instead of throwing and crashing the real (non-injected) run path.
const dockerExec = (name, cmdArray) => {
  const r = spawnSync("docker", ["exec", name, ...cmdArray], { stdio: "inherit" })
  if (r.error) return 3 // spawn failed (e.g. docker missing) -> fail-closed-ish
  return typeof r.status === "number" ? r.status : 1
}

export function runExec(argv, { rootDir, now, exec } = {}) {
  const stamp = (now ?? (() => new Date().toISOString()))()

  let cfg, cfgName
  try {
    cfg = loadActiveConfig(rootDir)
    cfgName = activeName(rootDir)
  } catch (e) {
    return { code: 3, message: `fail-closed: ${e.message}` }
  }

  // The real runner needs the per-engagement container name, which is only
  // known once cfgName has been resolved above — build it here so the
  // closure never reads cfgName before it exists.
  const runner = exec ?? ((cmdArray) => dockerExec(`omop-${cfgName}`, cmdArray))

  const { tool, target, extraArgs } = parse(argv)
  const auditPath = join(rootDir, "engagements", cfgName, "audit.log")
  const deny = (reason) => {
    appendAudit(auditPath, { ts: stamp, target, tool, decision: "DENY", reason, authorization: cfg.authorization })
    return { code: 2, message: `DENY ${reason}` }
  }

  if (!target) return deny("missing --target")
  if (cfg.scope_enforcement !== "none") {
    const m = matchTarget(target, cfg)
    if (m.decision === "DENY") return deny(m.reason)
  }
  const s = checkSafety(tool, extraArgs, cfg.safety_constraints)
  if (s.decision === "DENY") return deny(s.reason)

  // Catalog load / tool lookup can throw (CatalogError on missing/invalid
  // catalog file) — route that through deny() too, so it's audited and
  // exits 2 like every other refusal instead of an uncaught throw (Node's
  // default non-zero exit, no audit line).
  let entry
  try {
    const catalog = loadCatalog(join(rootDir, "tools-catalog.json"))
    entry = findTool(catalog, tool)
  } catch (e) {
    return deny(`catalog-error: ${e.message}`)
  }
  if (!entry) return deny(`unknown tool '${tool}'`)
  const cmdArray = buildCommand(entry, { target, extraArgs })

  appendAudit(auditPath, { ts: stamp, target, tool, decision: "ALLOW", reason: "passed", authorization: cfg.authorization })
  const code = runner(cmdArray) ?? 0
  return { code: typeof code === "number" ? code : 0, message: "ALLOW" }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and is undefined under Node,
// so it must not gate the entrypoint here — this file is meant to run under
// plain `node`. Use the same argv-identity idiom as hooks/scope-guard.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const r = runExec(process.argv.slice(2), { rootDir: process.env.CLAUDE_PROJECT_DIR ?? process.cwd() })
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
