// bin/bh-recon-map.mjs
//
// Thin CLI: reads the raw recon tool outputs for the active engagement and
// writes a normalized recon-map.json alongside them. Not a network tool —
// it only reads/merges files already produced by subfinder/httpx/nmap, so
// it runs as plain `node bin/bh-recon-map.mjs` (no docker exec involved).
import { join } from "node:path"
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { activeName } from "../src/scope/active-engagement.mjs"
import { buildReconMap } from "../src/recon/recon-map.mjs"
import { dataRoot } from "../src/paths.mjs"

// Missing input files are treated as empty text, not errors — a fresh
// engagement that has only run subfinder so far (no httpx/nmap yet) must
// still produce a partial recon-map, not crash.
const readOrEmpty = (path) => (existsSync(path) ? readFileSync(path, "utf8") : "")

export function runReconMap({ dataDir, now } = {}) {
  const dDir = dataDir ?? dataRoot()
  const name = activeName(dDir)
  if (!name) return { code: 3, message: "fail-closed: no active engagement" }

  const reconDir = join(dDir, "engagements", name, "output", "recon")
  const subfinderJsonl = readOrEmpty(join(reconDir, "subfinder.jsonl"))
  const httpxJsonl = readOrEmpty(join(reconDir, "httpx.jsonl"))
  // Concatenate every *.gnmap in the recon dir (one per host scanned, per
  // the pentest-recon skill's output layout) — sorted for deterministic
  // ordering regardless of filesystem readdir order.
  const gnmapFiles = existsSync(reconDir)
    ? readdirSync(reconDir).filter((f) => f.endsWith(".gnmap")).sort()
    : []
  const nmapGrepable = gnmapFiles.map((f) => readFileSync(join(reconDir, f), "utf8")).join("\n")

  const map = buildReconMap({ subfinderJsonl, httpxJsonl, nmapGrepable }, { now })

  // recon-map.json is written into the same recon dir the inputs came from.
  // mkdir -p defensively: a brand-new engagement that hasn't run any recon
  // tool yet won't have output/recon/ on disk at all.
  mkdirSync(reconDir, { recursive: true })
  const outPath = join(reconDir, "recon-map.json")
  writeFileSync(outPath, JSON.stringify(map, null, 2) + "\n")

  return { code: 0, message: `wrote ${outPath}`, path: outPath }
}

// Optional "--data-dir <path>" pair, same convention/rationale as
// bh-exec.mjs / bh-engagement.mjs: plugin-mode agent invocations pass the
// data dir explicitly since ${CLAUDE_PLUGIN_DATA} isn't exported to the
// agent's Bash tool session.
function extractDataDir(argv) {
  const i = argv.indexOf("--data-dir")
  if (i < 0) return { dataDir: null, rest: argv }
  const dataDir = argv[i + 1]
  return { dataDir, rest: [...argv.slice(0, i), ...argv.slice(i + 2)] }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here — same argv-identity idiom as
// bh-exec.mjs / bh-engagement.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir } = extractDataDir(process.argv.slice(2))
  const r = runReconMap(dataDir ? { dataDir } : {})
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
