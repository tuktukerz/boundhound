import { join } from "node:path"
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { codeRoot, dataRoot } from "../src/paths.mjs"

export function createEngagement(name, { rootDir, codeDir, dataDir, containerUp } = {}) {
  const cDir = codeDir ?? rootDir ?? codeRoot()
  const dDir = dataDir ?? rootDir ?? dataRoot()
  const dir = join(dDir, "engagements", name)
  mkdirSync(join(dir, "output"), { recursive: true })
  const scopePath = join(dir, "scope.yaml")
  if (!existsSync(scopePath)) {
    const tpl = readFileSync(join(cDir, "engagements", "templates", "scope.yaml"), "utf8")
    writeFileSync(scopePath, tpl.replace("REPLACE_ME", name))
  }
  writeFileSync(join(dDir, "engagements", ".active"), name)
  // Absolute path built from cDir (code root), not a bare relative path: a
  // bare "bin/bh-container" resolves against process.cwd(), which breaks
  // as soon as this runs from any directory other than the repo checkout
  // (e.g. plugin mode, or a foreign project dir). cDir is already resolved
  // above (CLAUDE_PLUGIN_ROOT in plugin mode, repo root in dev mode), so
  // reuse it here the same way runExec resolves the catalog path from cDir.
  const up = containerUp ?? ((n) => execFileSync(join(cDir, "bin", "bh-container"), ["up", n], { stdio: "inherit" }))
  up(name)
  return { path: dir }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  // Optional "--data-dir <path>" pair, same rationale as bh-exec.mjs:
  // ${CLAUDE_PLUGIN_DATA} is only exported as a real env var to hook/MCP/LSP
  // subprocesses, not to the agent's Bash tool session, so plugin-mode
  // invocations must pass the (content-substituted) data dir explicitly.
  const argv = process.argv.slice(2)
  const ddi = argv.indexOf("--data-dir")
  const dataDir = ddi >= 0 ? argv[ddi + 1] : null
  const rest = ddi >= 0 ? [...argv.slice(0, ddi), ...argv.slice(ddi + 2)] : argv
  const name = rest[0]
  if (!name) { process.stderr.write("usage: bh-engagement <name> [--data-dir <path>]\n"); process.exit(1) }
  const { path } = createEngagement(name, dataDir ? { dataDir } : {})
  process.stdout.write(`engagement ready: ${path}\nedit scope.yaml, then run tools via bh-exec.\n`)
}
