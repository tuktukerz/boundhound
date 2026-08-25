// bin/bh-fullscan.mjs
//
// Thin CLI: wires the REAL bh-exec runner + the REAL synth CLIs into the
// staged driver (src/orchestrate/fullscan.mjs's runFullscan). This file
// never runs a tool directly -- every tool step is dispatched as
// `node bin/bh-exec.mjs <tool> --target <t> --data-dir <d> -- <flags>`,
// exactly the same choke point a manual operator goes through (spec §3).
// The runner/synth/loadMaps builders below take an injectable `spawn`
// (defaulting to node:child_process's spawnSync) so a unit test can stub the
// process boundary and assert the constructed commands without ever
// touching docker -- see bin/bh-fullscan.test.mjs.
import { join } from "node:path"
import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { activeName, loadActiveConfig } from "../src/scope/active-engagement.mjs"
import { runFullscan as runFullscanCore } from "../src/orchestrate/fullscan.mjs"
import { codeRoot, dataRoot } from "../src/paths.mjs"

// Which output file a tool's captured stdout is written into, and how
// (append vs overwrite), so the corresponding map-builder (bh-recon-map/
// bh-enum-map/bh-exploit-map) can read it back -- must match exactly where
// those CLIs read from (re-verified against bin/bh-recon-map.mjs,
// bin/bh-enum-map.mjs, bin/bh-exploit-map.mjs).
//   - subfinder/httpx write into ONE shared file across all their steps
//     (bh-recon-map concatenates subfinder.jsonl/httpx.jsonl as a whole) ->
//     append.
//   - nmap/nuclei/ffuf/sqlmap each get their OWN file keyed by the target's
//     host (bh-recon-map globs every *.gnmap; bh-enum-map globs every
//     nuclei*.jsonl/ffuf*.json; bh-exploit-map globs every *.sqlmap.txt) ->
//     one write per host is enough (a full-scan run only ever plans one
//     step per host per stage).
const OUTPUT_RULES = {
  subfinder: { dir: "recon", file: () => "subfinder.jsonl", mode: "append" },
  httpx: { dir: "recon", file: () => "httpx.jsonl", mode: "append" },
  nmap: { dir: "recon", file: (host) => `${host}.gnmap`, mode: "write" },
  nuclei: { dir: "enum", file: (host) => `nuclei-${host}.jsonl`, mode: "write" },
  ffuf: { dir: "enum", file: (host) => `ffuf-${host}.json`, mode: "write" },
  sqlmap: { dir: "exploit", file: (host) => `${host}.sqlmap.txt`, mode: "write" },
}

// Every synthesizer CLI runFullscan's `synth(kind)` can be asked for, and
// the bin file that implements it.
const SYNTH_BIN = {
  "recon-map": "bh-recon-map.mjs",
  "enum-map": "bh-enum-map.mjs",
  "exploit-map": "bh-exploit-map.mjs",
  findings: "bh-findings.mjs",
  report: "bh-report.mjs",
}

// The hostname a step's output file is keyed on. nmap's target is already a
// bare host ("acme.io"); httpx/nuclei/ffuf/sqlmap targets are URLs -- the
// URL constructor pulls the hostname back out. A target the URL constructor
// rejects (a bare host, a malformed value) falls back to the raw target
// string rather than throwing.
function deriveHost(target) {
  try {
    return new URL(target).hostname || String(target)
  } catch {
    return String(target)
  }
}

// A discovered host is untrusted input (subfinder/enum output) even though
// it already cleared scope -- never let it be used as a raw path segment.
// Keeps [A-Za-z0-9._-], replaces everything else (including "/" and "..")
// with "_" so a step's output path can never escape its output directory.
function safeFilenamePart(s) {
  return String(s).replace(/[^A-Za-z0-9._-]/g, "_")
}

// The real `runner` (spec §3): spawns bh-exec for one planned step, capturing
// its stdout and filing it under the stage's output directory so the next
// synth() call can pick it up. A DENY (exit 2) or any other non-zero exit is
// logged and skipped -- never thrown -- so one denied/failed step never
// aborts the rest of the scan (runFullscan already treats a throw the same
// way, but there is nothing exceptional about a bh-exec DENY: it is the
// system working as designed).
function makeRunner({ codeDir, dataDir, name, spawn, log }) {
  return ({ tool, target, flags, stage }) => {
    const args = [join(codeDir, "bin", "bh-exec.mjs"), tool, "--target", target, "--data-dir", dataDir, "--", ...(flags ?? [])]
    const result = spawn("node", args, { encoding: "utf8" }) ?? {}
    const code = typeof result.status === "number" ? result.status : result.error ? -1 : 0

    if (code === 2) {
      log(`stage ${stage}: DENY ${tool} ${target}`)
      return
    }
    if (code !== 0) {
      log(`stage ${stage}: ${tool} ${target} exited ${code}, skipping output capture`)
      return
    }

    const rule = OUTPUT_RULES[tool]
    if (!rule) {
      log(`stage ${stage}: no known output file for tool '${tool}', discarding stdout`)
      return
    }

    const outDir = join(dataDir, "engagements", name, "output", rule.dir)
    mkdirSync(outDir, { recursive: true })
    const host = safeFilenamePart(deriveHost(target))
    const outPath = join(outDir, rule.file(host))
    const stdout = typeof result.stdout === "string" ? result.stdout : ""

    if (rule.mode === "append") {
      appendFileSync(outPath, stdout.length === 0 || stdout.endsWith("\n") ? stdout : `${stdout}\n`)
    } else {
      writeFileSync(outPath, stdout)
    }
    log(`stage ${stage}: ${tool} ${target} -> ${outPath}`)
  }
}

// The real `synth` (spec §3): spawns the corresponding bh-<kind> CLI, which
// re-reads whatever the runner just wrote and rebuilds/advances the
// relevant *-map.json / findings.json / report.md. A non-zero exit is
// logged, never thrown.
function makeSynth({ codeDir, dataDir, spawn, log }) {
  return (kind) => {
    const bin = SYNTH_BIN[kind]
    if (!bin) {
      log(`synth: unknown kind '${kind}'`)
      return
    }
    const args = [join(codeDir, "bin", bin), "--data-dir", dataDir]
    const result = spawn("node", args, { encoding: "utf8" }) ?? {}
    const code = typeof result.status === "number" ? result.status : result.error ? -1 : 0
    if (code !== 0) log(`synth(${kind}) exited ${code}`)
  }
}

// The real `loadMaps` (spec §3): re-reads the current recon-map.json /
// enum-map.json from disk before every stage. Missing or invalid JSON both
// mean "nothing built yet" -> null, same tolerance policy as bh-findings.mjs's
// readMapOrNull -- a stage must never throw just because an earlier phase
// hasn't run.
function readJsonOrNull(path) {
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, "utf8"))
  } catch {
    return null
  }
}

function makeLoadMaps({ dataDir, name }) {
  return () => ({
    reconMap: readJsonOrNull(join(dataDir, "engagements", name, "output", "recon", "recon-map.json")),
    enumMap: readJsonOrNull(join(dataDir, "engagements", name, "output", "enum", "enum-map.json")),
  })
}

// runFullscan (CLI level): fail-closed on no active engagement / broken
// scope via loadActiveConfig (spec §3) -- on throw, return code 3 and run
// NOTHING (no runner/synth/loadMaps is ever constructed, let alone called).
// `spawn` is injectable (defaults to node:child_process's spawnSync) purely
// for testability -- production always uses the real one.
export async function runFullscan({ dataDir, exploit = true, spawn = spawnSync, log } = {}) {
  const dDir = dataDir ?? dataRoot()
  const cDir = codeRoot()

  let cfg
  try {
    cfg = loadActiveConfig(dDir)
  } catch (e) {
    return { code: 3, message: `fail-closed: ${e.message}` }
  }
  const name = activeName(dDir)

  const doLog = typeof log === "function" ? log : (line) => process.stderr.write(`${line}\n`)

  const runner = makeRunner({ codeDir: cDir, dataDir: dDir, name, spawn, log: doLog })
  const synth = makeSynth({ codeDir: cDir, dataDir: dDir, spawn, log: doLog })
  const loadMaps = makeLoadMaps({ dataDir: dDir, name })

  const summary = await runFullscanCore({ runner, synth, loadMaps, scope: cfg, log: doLog }, { exploit })

  const reportPath = join(dDir, "engagements", name, "output", "report", "report.md")
  return { code: 0, message: `fullscan complete -> ${reportPath}`, summary, path: reportPath }
}

// Optional "--data-dir <path>" pair (same convention/rationale as every
// other bin: plugin-mode agent invocations pass the data dir explicitly
// since ${CLAUDE_PLUGIN_DATA} isn't exported to the agent's Bash tool
// session) plus an optional "--no-exploit" flag (spec §3) that disables the
// exploit:sqlmap stage for a fully non-intrusive recon+enum+report run.
function extractFlags(argv) {
  let rest = argv
  let dataDir = null

  const ddi = rest.indexOf("--data-dir")
  if (ddi >= 0) {
    dataDir = rest[ddi + 1]
    rest = [...rest.slice(0, ddi), ...rest.slice(ddi + 2)]
  }

  let noExploit = false
  const nei = rest.indexOf("--no-exploit")
  if (nei >= 0) {
    noExploit = true
    rest = [...rest.slice(0, nei), ...rest.slice(nei + 1)]
  }

  return { dataDir, noExploit, rest }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here -- same argv-identity idiom as every
// other bin (bh-exec.mjs / bh-report.mjs / bh-recon-map.mjs / ...).
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir, noExploit } = extractFlags(process.argv.slice(2))
  runFullscan({ dataDir: dataDir ?? undefined, exploit: !noExploit }).then((r) => {
    if (r.message) process.stderr.write(r.message + "\n")
    process.exit(r.code)
  })
}
