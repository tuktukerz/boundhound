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
import { emptyState, parseState, serializeState } from "../src/orchestrate/run-state.mjs"
import { codeRoot, dataRoot } from "../src/paths.mjs"

// Which output file a tool's captured stdout is written into, and how
// (append vs overwrite), so the corresponding map-builder (bh-recon-map/
// bh-enum-map/bh-exploit-map) can read it back -- must match exactly where
// those CLIs read from (re-verified against bin/bh-recon-map.mjs,
// bin/bh-enum-map.mjs, bin/bh-exploit-map.mjs).
//
// Invariant: within a single run, no two planned steps' captured stdout may
// ever overwrite each other. A run CAN plan more than one step per host per
// stage -- e.g. exploit:sqlmap draws candidate URLs from enumMap.content
// (ffuf's match results), and ffuf routinely returns many matches on one
// host that still share the same query key, so the driver's dedupe() does
// NOT collapse them into one sqlmap step. The same structural hazard
// applies to nuclei/ffuf if http_services ever carries >1 URL for one host.
// So each format is handled per its own concatenability:
//   - subfinder/httpx write into ONE shared file across all their steps
//     (bh-recon-map concatenates subfinder.jsonl/httpx.jsonl as a whole) ->
//     append.
//   - nmap gets its OWN file keyed by the target's host (bh-recon-map globs
//     every *.gnmap) -> write is safe: the planner dedupes hosts before
//     ever building an nmap step, so nmap never plans two steps for the
//     same host in one run.
//   - nuclei is JSONL (line-delimited) -- bh-enum-map reads the whole
//     nuclei*.jsonl file line by line, so concatenating multiple steps'
//     records is correct -> append, same pattern as subfinder/httpx.
//   - sqlmap is a plain-text blob -- bh-exploit-map reads the whole
//     *.sqlmap.txt file as one string, so concatenating multiple
//     steps'/hosts' output is safe -> append.
//   - ffuf is a single JSON document and CANNOT be concatenated (that would
//     produce invalid JSON) -> keep "write", but make the filename unique
//     per step via a deterministic per-host counter (see `ffufStepCounts`
//     in makeRunner below) so two ffuf steps for the same host land in two
//     different files instead of colliding. bh-enum-map globs every
//     ffuf*.json file and parses each as its own JSON document, so several
//     ffuf-<host>-<n>.json files are read and merged correctly.
const OUTPUT_RULES = {
  subfinder: { dir: "recon", file: () => "subfinder.jsonl", mode: "append" },
  httpx: { dir: "recon", file: () => "httpx.jsonl", mode: "append" },
  nmap: { dir: "recon", file: (host) => `${host}.gnmap`, mode: "write" },
  nuclei: { dir: "enum", file: (host) => `nuclei-${host}.jsonl`, mode: "append" },
  ffuf: { dir: "enum", file: (host, n) => `ffuf-${host}-${n}.json`, mode: "write" },
  sqlmap: { dir: "exploit", file: (host) => `${host}.sqlmap.txt`, mode: "append" },
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
//
// Phase 7 (spec §4): now RETURNS `{status}` so the driver (runFullscanCore)
// can classify the outcome for resume/retry -- exit 0 -> "ok", exit 2
// (DENY) -> "denied", any other nonzero exit or spawn error -> "transient".
// This is purely an added return value: the DENY log-and-skip and the
// output-capture-only-on-exit-0 behavior are both unchanged from before.
export function makeRunner({ codeDir, dataDir, name, spawn, log }) {
  // Deterministic per-run, per-host counter for ffuf's output filename (the
  // only tool that keeps "write" mode -- its JSON output can't be
  // concatenated). A plain Map held in this closure, incremented once per
  // ffuf step for a given host: Date.now()/Math.random()/argless `new
  // Date()` all throw in this codebase, so a counter is the only
  // deterministic source of per-step uniqueness available here.
  const ffufStepCounts = new Map()

  return ({ tool, target, flags, stage }) => {
    const args = [join(codeDir, "bin", "bh-exec.mjs"), tool, "--target", target, "--data-dir", dataDir, "--", ...(flags ?? [])]
    const result = spawn("node", args, { encoding: "utf8" }) ?? {}
    const code = typeof result.status === "number" ? result.status : result.error ? -1 : 0

    if (code === 2) {
      log(`stage ${stage}: DENY ${tool} ${target}`)
      return { status: "denied" }
    }
    if (code !== 0) {
      log(`stage ${stage}: ${tool} ${target} exited ${code}, skipping output capture`)
      return { status: "transient" }
    }

    const rule = OUTPUT_RULES[tool]
    if (!rule) {
      log(`stage ${stage}: no known output file for tool '${tool}', discarding stdout`)
      return { status: "ok" }
    }

    const outDir = join(dataDir, "engagements", name, "output", rule.dir)
    mkdirSync(outDir, { recursive: true })
    const host = safeFilenamePart(deriveHost(target))
    let filename
    if (tool === "ffuf") {
      const next = (ffufStepCounts.get(host) ?? 0) + 1
      ffufStepCounts.set(host, next)
      filename = rule.file(host, next)
    } else {
      filename = rule.file(host)
    }
    const outPath = join(outDir, filename)
    const stdout = typeof result.stdout === "string" ? result.stdout : ""

    if (rule.mode === "append") {
      appendFileSync(outPath, stdout.length === 0 || stdout.endsWith("\n") ? stdout : `${stdout}\n`)
    } else {
      writeFileSync(outPath, stdout)
    }
    log(`stage ${stage}: ${tool} ${target} -> ${outPath}`)
    return { status: "ok" }
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

// The real `loadState`/`saveState` (spec §4): the resume state file lives at
// engagements/<active>/output/fullscan-state.json, a sibling of the
// recon/enum/exploit output subdirectories makeRunner writes into. Both
// directions defer their tolerance entirely to run-state.mjs's own
// parseState/serializeState (Task 1) -- a missing or malformed file must
// resume as "nothing done yet", never throw and abort the very scan it
// exists to make resumable.
function statePath(dataDir, name) {
  return join(dataDir, "engagements", name, "output", "fullscan-state.json")
}

function makeLoadState({ dataDir, name }) {
  const path = statePath(dataDir, name)
  return () => {
    if (!existsSync(path)) return emptyState()
    try {
      return parseState(readFileSync(path, "utf8"))
    } catch {
      return emptyState()
    }
  }
}

function makeSaveState({ dataDir, name }) {
  const outDir = join(dataDir, "engagements", name, "output")
  const path = statePath(dataDir, name)
  return (state) => {
    mkdirSync(outDir, { recursive: true })
    writeFileSync(path, serializeState(state))
  }
}

// The real `sleep` (spec §4): setTimeout-based, injectable purely so tests
// never actually wait. Backoff is bounded exponential with NO random jitter
// (this codebase forbids Math.random() -- see makeRunner's ffufStepCounts
// comment above for why) so a given attempt number always yields the exact
// same delay, forever.
const RETRY_BASE_MS = 500
const RETRY_CAP_MS = 8000

function realSleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export function backoff(attempt) {
  return Math.min(RETRY_BASE_MS * 2 ** attempt, RETRY_CAP_MS)
}

// runFullscan (CLI level): fail-closed on no active engagement / broken
// scope via loadActiveConfig (spec §3) -- on throw, return code 3 and run
// NOTHING (no runner/synth/loadMaps is ever constructed, let alone called).
// `spawn` is injectable (defaults to node:child_process's spawnSync) purely
// for testability -- production always uses the real one.
export async function runFullscan({
  dataDir,
  exploit = true,
  spawn = spawnSync,
  log,
  resume = false,
  maxRetries = 0,
  maxSteps,
  maxStepsPerStage,
  sleep = realSleep,
} = {}) {
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
  const loadState = makeLoadState({ dataDir: dDir, name })
  const saveState = makeSaveState({ dataDir: dDir, name })

  // Budget fields are only ever set when the corresponding flag was actually
  // passed -- runFullscanCore gates every budget check on `typeof === "number"`,
  // so an omitted field (rather than e.g. undefined explicitly assigned) is
  // what keeps a caller that passes neither flag byte-for-byte identical to
  // today's unbounded run.
  const budget = {}
  if (typeof maxSteps === "number") budget.maxSteps = maxSteps
  if (typeof maxStepsPerStage === "number") budget.maxStepsPerStage = maxStepsPerStage

  const summary = await runFullscanCore(
    { runner, synth, loadMaps, loadState, saveState, sleep, scope: cfg, log: doLog },
    { exploit, resume, retry: { maxRetries, backoff }, budget }
  )

  const reportPath = join(dDir, "engagements", name, "output", "report", "report.md")
  return { code: 0, message: `fullscan complete -> ${reportPath}`, summary, path: reportPath }
}

// Optional "--data-dir <path>" pair (same convention/rationale as every
// other bin: plugin-mode agent invocations pass the data dir explicitly
// since ${CLAUDE_PLUGIN_DATA} isn't exported to the agent's Bash tool
// session) plus an optional "--no-exploit" flag (spec §3) that disables the
// exploit:sqlmap stage for a fully non-intrusive recon+enum+report run.
//
// Phase 7 resilience (spec §4) adds four more flags, parsed the same style:
//   --resume                  bool, same shape as --no-exploit
//   --max-retries N           number, default 0 (today's single-attempt)
//   --max-steps N             number, no default -- absent means "no budget"
//   --max-steps-per-stage N   number, same "absent means no budget" rule
// maxSteps/maxStepsPerStage are left `undefined` (not defaulted to a number)
// when the flag isn't given, because runFullscan (CLI level) only sets a
// budget field when it sees a real number -- see its own comment.
export function extractFlags(argv) {
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

  let resume = false
  const ri = rest.indexOf("--resume")
  if (ri >= 0) {
    resume = true
    rest = [...rest.slice(0, ri), ...rest.slice(ri + 1)]
  }

  let maxRetries = 0
  const mri = rest.indexOf("--max-retries")
  if (mri >= 0) {
    const n = Number(rest[mri + 1])
    if (Number.isFinite(n)) {
      maxRetries = n
      rest = [...rest.slice(0, mri), ...rest.slice(mri + 2)]
    } else {
      // The value token is missing or not a valid number -- e.g. the flag
      // was the last argv token, or the "value" is actually the NEXT
      // recognized flag (a caller typo like "--max-retries --max-steps 5").
      // Strip ONLY the flag itself so that next flag's own token is never
      // eaten by this one's slice(idx, idx+2) -- swallowing it would
      // silently leave --max-steps (a safety-positive run-budget ceiling)
      // unset with no indication anything went wrong, which is worse than
      // just ignoring this malformed flag loudly.
      process.stderr.write("warning: --max-retries given without a valid numeric value; ignoring\n")
      rest = [...rest.slice(0, mri), ...rest.slice(mri + 1)]
    }
  }

  let maxSteps
  const msi = rest.indexOf("--max-steps")
  if (msi >= 0) {
    const n = Number(rest[msi + 1])
    if (Number.isFinite(n)) {
      maxSteps = n
      rest = [...rest.slice(0, msi), ...rest.slice(msi + 2)]
    } else {
      process.stderr.write("warning: --max-steps given without a valid numeric value; ignoring\n")
      rest = [...rest.slice(0, msi), ...rest.slice(msi + 1)]
    }
  }

  let maxStepsPerStage
  const mspsi = rest.indexOf("--max-steps-per-stage")
  if (mspsi >= 0) {
    const n = Number(rest[mspsi + 1])
    if (Number.isFinite(n)) {
      maxStepsPerStage = n
      rest = [...rest.slice(0, mspsi), ...rest.slice(mspsi + 2)]
    } else {
      process.stderr.write("warning: --max-steps-per-stage given without a valid numeric value; ignoring\n")
      rest = [...rest.slice(0, mspsi), ...rest.slice(mspsi + 1)]
    }
  }

  return { dataDir, noExploit, resume, maxRetries, maxSteps, maxStepsPerStage, rest }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here -- same argv-identity idiom as every
// other bin (bh-exec.mjs / bh-report.mjs / bh-recon-map.mjs / ...).
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir, noExploit, resume, maxRetries, maxSteps, maxStepsPerStage } = extractFlags(process.argv.slice(2))
  runFullscan({ dataDir: dataDir ?? undefined, exploit: !noExploit, resume, maxRetries, maxSteps, maxStepsPerStage })
    .then((r) => {
      if (r.message) process.stderr.write(r.message + "\n")
      process.exit(r.code)
    })
    .catch((err) => {
      // Fail-closed on any unexpected rejection on the entry path: a short
      // stderr message + non-zero exit, never a raw Node stack trace, and
      // never silently swallowed.
      process.stderr.write(`bh-fullscan: unexpected error: ${err && err.message ? err.message : String(err)}\n`)
      process.exit(1)
    })
}
