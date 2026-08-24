// bin/bh-enum-map.mjs
//
// Thin CLI: reads the raw enum tool outputs for the active engagement and
// writes a normalized enum-map.json alongside them. Not a network tool —
// it only reads/merges files already produced by ffuf/nuclei, so it runs as
// plain `node bin/bh-enum-map.mjs` (no docker exec involved).
import { join } from "node:path"
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { activeName } from "../src/scope/active-engagement.mjs"
import { buildEnumMap, parseFfufJson } from "../src/enum/enum-map.mjs"
import { dataRoot } from "../src/paths.mjs"

export function runEnumMap({ dataDir, now } = {}) {
  const dDir = dataDir ?? dataRoot()
  const name = activeName(dDir)
  if (!name) return { code: 3, message: "fail-closed: no active engagement" }

  const enumDir = join(dDir, "engagements", name, "output", "enum")
  const files = existsSync(enumDir) ? readdirSync(enumDir).sort() : []

  // Each ffuf*.json file is its own JSON blob (one ffuf run's -of json
  // output), not line-oriented like nuclei's output — so they can't be
  // concatenated as text. Parse every matching file separately and merge
  // the resulting content arrays. Missing files just mean an empty list.
  const content = files
    .filter((f) => f.startsWith("ffuf") && f.endsWith(".json"))
    .flatMap((f) => parseFfufJson(readFileSync(join(enumDir, f), "utf8")))

  // nuclei*.jsonl files are line-oriented (one JSON object per line), so —
  // like recon's *.gnmap files — they concatenate fine as plain text.
  const nucleiJsonl = files
    .filter((f) => f.startsWith("nuclei") && f.endsWith(".jsonl"))
    .map((f) => readFileSync(join(enumDir, f), "utf8"))
    .join("\n")

  const map = buildEnumMap({ ffufJson: "", nucleiJsonl }, { now })
  map.content = content

  // enum-map.json is written into the same enum dir the inputs came from.
  // mkdir -p defensively: a brand-new engagement that hasn't run any enum
  // tool yet won't have output/enum/ on disk at all.
  mkdirSync(enumDir, { recursive: true })
  const outPath = join(enumDir, "enum-map.json")
  writeFileSync(outPath, JSON.stringify(map, null, 2) + "\n")

  return { code: 0, message: `wrote ${outPath}`, path: outPath }
}

// Optional "--data-dir <path>" pair, same convention/rationale as
// bh-exec.mjs / bh-engagement.mjs / bh-recon-map.mjs: plugin-mode agent
// invocations pass the data dir explicitly since ${CLAUDE_PLUGIN_DATA}
// isn't exported to the agent's Bash tool session.
function extractDataDir(argv) {
  const i = argv.indexOf("--data-dir")
  if (i < 0) return { dataDir: null, rest: argv }
  const dataDir = argv[i + 1]
  return { dataDir, rest: [...argv.slice(0, i), ...argv.slice(i + 2)] }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here — same argv-identity idiom as
// bh-exec.mjs / bh-engagement.mjs / bh-recon-map.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir } = extractDataDir(process.argv.slice(2))
  const r = runEnumMap(dataDir ? { dataDir } : {})
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
