// bin/bh-exec.mjs
import { join } from "node:path"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { loadActiveConfig, activeName } from "../src/scope/active-engagement.mjs"
import { matchTarget } from "../src/scope/scope-matcher.mjs"
import { checkSafety } from "../src/safety/safety-check.mjs"
import { loadCatalog, findTool } from "../src/catalog/catalog-loader.mjs"
import { buildCommand } from "../src/command-builder/command-builder.mjs"
import { appendAudit } from "../src/audit/audit-log.mjs"
import { codeRoot, dataRoot } from "../src/paths.mjs"

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
// Sentinel returned when the docker spawn itself fails (docker missing,
// permission denied, etc.) — distinct from the "no active engagement"
// fail-closed exit-3 in runExec, so the two code-3 paths aren't confused
// when threading through the final return message below.
const DOCKER_SPAWN_FAILED = 3
const dockerExec = (name, cmdArray) => {
  const r = spawnSync("docker", ["exec", name, ...cmdArray], { stdio: "inherit" })
  if (r.error) return DOCKER_SPAWN_FAILED // spawn failed (e.g. docker missing) -> fail-closed-ish
  return typeof r.status === "number" ? r.status : 1
}

export function runExec(argv, { rootDir, codeDir, dataDir, now, exec } = {}) {
  const cDir = codeDir ?? rootDir ?? codeRoot()
  const dDir = dataDir ?? rootDir ?? dataRoot()
  const stamp = (now ?? (() => new Date().toISOString()))()

  let cfg, cfgName
  try {
    cfg = loadActiveConfig(dDir)
    cfgName = activeName(dDir)
  } catch (e) {
    return { code: 3, message: `fail-closed: ${e.message}` }
  }

  // The real runner needs the per-engagement container name, which is only
  // known once cfgName has been resolved above — build it here so the
  // closure never reads cfgName before it exists.
  const runner = exec ?? ((cmdArray) => dockerExec(`bh-${cfgName}`, cmdArray))

  const { tool, target, extraArgs } = parse(argv)
  const auditPath = join(dDir, "engagements", cfgName, "audit.log")
  const deny = (reason) => {
    appendAudit(auditPath, { ts: stamp, target, tool, decision: "DENY", reason, authorization: cfg.authorization })
    return { code: 2, message: `DENY ${reason}` }
  }

  if (!target) return deny("missing --target")
  let m = null
  if (cfg.scope_enforcement !== "none") {
    m = matchTarget(target, cfg)
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
    const catalog = loadCatalog(join(cDir, "tools-catalog.json"))
    entry = findTool(catalog, tool)
  } catch (e) {
    return deny(`catalog-error: ${e.message}`)
  }
  if (!entry) return deny(`unknown tool '${tool}'`)

  // extraArgs is otherwise passed straight through to the real command line
  // (see buildCommand below). Without this check, a bare URL/host smuggled
  // in extraArgs never gets scope-checked — only --target does — while the
  // tool itself (e.g. curl) happily treats a trailing positional as the
  // real destination ("target-smuggling"). Every token must be a flag the
  // catalog explicitly declares for this tool; a bare URL is never a
  // declared flag name, so this closes the hole.
  const declaredFlags = new Set((entry.command.flags ?? []).map((f) => f.name))
  for (const arg of extraArgs) {
    if (!declaredFlags.has(arg)) {
      return deny(`extraArgs contains undeclared token '${arg}' (not a declared flag for '${tool}')`)
    }
  }

  const cmdArray = buildCommand(entry, { target, extraArgs })

  appendAudit(auditPath, {
    ts: stamp,
    target,
    tool,
    decision: "ALLOW",
    reason: m?.reason ?? "scope_enforcement:none",
    authorization: cfg.authorization,
  })
  const code = runner(cmdArray) ?? 0
  if (code === DOCKER_SPAWN_FAILED) {
    return { code, message: "EXEC-ERROR (docker spawn failed)" }
  }
  return { code: typeof code === "number" ? code : 0, message: "ALLOW" }
}

// Extracts an optional "--data-dir <path>" pair from argv before it reaches
// parse()/runExec. Plugin-mode agent invocations pass this explicitly (see
// .claude/commands/engagement.md and pentest-mode/SKILL.md) because
// ${CLAUDE_PLUGIN_DATA} is only exported as a real env var to hook/MCP/LSP
// subprocesses, not to the agent's Bash tool session — the CLI process
// spawned from Bash never sees it, so dataRoot()'s env-var fallback silently
// resolves to cwd instead. Only scanned ahead of the "--" separator (if any)
// so a real tool flag of the same name passed through to the underlying
// tool after "--" is never mistaken for this CLI's own flag.
function extractDataDir(argv) {
  const dd = argv.indexOf("--")
  const head = dd >= 0 ? argv.slice(0, dd) : argv
  const tail = dd >= 0 ? argv.slice(dd) : []
  const i = head.indexOf("--data-dir")
  if (i < 0) return { dataDir: null, rest: argv }
  const dataDir = head[i + 1]
  const newHead = [...head.slice(0, i), ...head.slice(i + 2)]
  return { dataDir, rest: [...newHead, ...tail] }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and is undefined under Node,
// so it must not gate the entrypoint here — this file is meant to run under
// plain `node`. Use the same argv-identity idiom as hooks/scope-guard.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir, rest } = extractDataDir(process.argv.slice(2))
  const r = runExec(rest, dataDir ? { dataDir } : {})
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
