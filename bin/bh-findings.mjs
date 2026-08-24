// bin/bh-findings.mjs
//
// Thin CLI: reads the three per-tool maps (recon-map/enum-map/exploit-map)
// plus any re-verification tool outputs for the active engagement, and
// writes a consolidated + re-verified findings.json. Not a network tool —
// it only reads/merges files already produced by earlier phases and the
// pentest-verify skill's rechecks, so it runs as plain
// `node bin/bh-findings.mjs` (no docker exec involved).
import { join } from "node:path"
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { activeName } from "../src/scope/active-engagement.mjs"
import { buildFindings, applyVerification } from "../src/verify/findings.mjs"
import { parseNucleiJsonl } from "../src/enum/enum-map.mjs"
import { parseHttpxJsonl, parseNmapGrepable } from "../src/recon/recon-map.mjs"
import { dataRoot } from "../src/paths.mjs"

// Reads a previously-written *-map.json (recon-map.json/enum-map.json/
// exploit-map.json). Each of the three maps is optional per spec §3 — a
// missing file (that phase hasn't run yet) or invalid JSON (a half-written
// file, garbage) both mean "nothing to contribute" -> null, which
// buildFindings already tolerates (a null map contributes zero findings).
function readMapOrNull(path) {
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, "utf8"))
  } catch {
    return null
  }
}

// Turns one recheck output file's raw text into recheckResults shaped
// exactly like findings.mjs's matchesRecheck expects: {type, target, key,
// reproduced:true}. Dispatch is by filename, same prefix/suffix idiom as
// bh-enum-map.mjs's ffuf*/nuclei* split:
//   - "*.httpx.jsonl"      -> httpx recheck (http-service findings)
//   - "*.gnmap"            -> nmap recheck (open-port findings)
//   - "*.jsonl" / "nuclei*" -> nuclei recheck (nuclei findings)
// Anything else is skipped rather than guessed at. Every entry a tool
// actually emits here means "reproduced" — httpx/nuclei only ever write a
// line for a target that responded/matched, and nmap's grepable output is
// filtered to ports still reported "open" — so a target that no longer
// reproduces is simply absent from the recheck file, which is exactly the
// "leave verified:false" case applyVerification already handles.
function recheckResultsFor(filename, text) {
  if (filename.endsWith(".httpx.jsonl")) {
    return parseHttpxJsonl(text).map((s) => ({ type: "http-service", target: s.url, reproduced: true }))
  }
  if (filename.endsWith(".gnmap")) {
    return parseNmapGrepable(text).flatMap((h) =>
      h.ports
        .filter((p) => p.state === "open")
        .map((p) => ({ type: "open-port", target: h.host, key: p.port, reproduced: true }))
    )
  }
  if (filename.endsWith(".jsonl") || filename.startsWith("nuclei")) {
    return parseNucleiJsonl(text).map((f) => ({ type: "nuclei", target: f.host, key: f.template_id, reproduced: true }))
  }
  return []
}

export function runFindings({ dataDir, now } = {}) {
  const dDir = dataDir ?? dataRoot()
  const name = activeName(dDir)
  if (!name) return { code: 3, message: "fail-closed: no active engagement" }

  const outputDir = join(dDir, "engagements", name, "output")
  const reconMap = readMapOrNull(join(outputDir, "recon", "recon-map.json"))
  const enumMap = readMapOrNull(join(outputDir, "enum", "enum-map.json"))
  const exploitMap = readMapOrNull(join(outputDir, "exploit", "exploit-map.json"))

  // output/verify/recheck/* holds whatever re-verification tool outputs the
  // pentest-verify skill produced by re-running each candidate's SAME
  // bounded check via bh-exec (spec §2.3/§4) — sorted for deterministic
  // ordering regardless of readdir order. Missing dir just means "no
  // re-verification has happened yet" -> no recheck results, not an error.
  const recheckDir = join(outputDir, "verify", "recheck")
  const recheckFiles = existsSync(recheckDir) ? readdirSync(recheckDir).sort() : []
  const recheckResults = recheckFiles.flatMap((f) =>
    recheckResultsFor(f, readFileSync(join(recheckDir, f), "utf8"))
  )

  const map = buildFindings({ reconMap, enumMap, exploitMap }, { now })
  const findings = applyVerification(map.findings, recheckResults)

  // findings.json is written into output/verify/, alongside the recheck/
  // dir it may have just read from. mkdir -p defensively: an engagement
  // that hasn't run any earlier phase yet won't have output/verify/ on
  // disk at all.
  const verifyDir = join(outputDir, "verify")
  mkdirSync(verifyDir, { recursive: true })
  const outPath = join(verifyDir, "findings.json")
  writeFileSync(outPath, JSON.stringify({ generated_at: map.generated_at, findings }, null, 2) + "\n")

  return { code: 0, message: `wrote ${outPath}`, path: outPath }
}

// Optional "--data-dir <path>" pair, same convention/rationale as
// bh-exec.mjs / bh-engagement.mjs / bh-enum-map.mjs / bh-recon-map.mjs /
// bh-exploit-map.mjs: plugin-mode agent invocations pass the data dir
// explicitly since ${CLAUDE_PLUGIN_DATA} isn't exported to the agent's Bash
// tool session.
function extractDataDir(argv) {
  const i = argv.indexOf("--data-dir")
  if (i < 0) return { dataDir: null, rest: argv }
  const dataDir = argv[i + 1]
  return { dataDir, rest: [...argv.slice(0, i), ...argv.slice(i + 2)] }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here — same argv-identity idiom as
// bh-exec.mjs / bh-engagement.mjs / bh-enum-map.mjs / bh-recon-map.mjs /
// bh-exploit-map.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir } = extractDataDir(process.argv.slice(2))
  const r = runFindings(dataDir ? { dataDir } : {})
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
