// src/orchestrate/fullscan.mjs
//
// Phase 6 orchestrator core (spec §2): a PURE stage planner (`targetsForStage`)
// plus an INJECTABLE staged driver (`runFullscan`) that sequences the
// already-bounded recon/enum/exploit tool chain. Neither function here ever
// runs a tool directly -- `targetsForStage` only ever *describes* a step
// ({tool,target,flags}) for a caller (bin/bh-fullscan.mjs's real runner) to
// execute through bh-exec, and `runFullscan` only ever calls the `runner`/
// `synth`/`loadMaps` functions it is given. Every flag list below is copied
// verbatim from the already-cataloged/declared bounded flags the per-phase
// skills (pentest-recon/pentest-enum/pentest-exploit) already use -- this
// module introduces no new capability.
//
// Like recon-map/enum-map/findings, every function here tolerates missing or
// garbage input rather than throwing: an engagement's maps/scope are not a
// contract this module controls, and a broken map must never take down the
// whole scan.

import { matchTarget } from "../scope/scope-matcher.mjs"
import { stepKey, emptyState, isDone, markDone } from "./run-state.mjs"

const STAGE_ORDER = ["recon:subfinder", "recon:httpx", "recon:nmap", "enum:nuclei", "enum:ffuf", "exploit:sqlmap"]

// Which normalized map a stage's output feeds back into, per spec §2.3 --
// recon stages rebuild recon-map.json, enum stages rebuild enum-map.json,
// exploit rebuilds exploit-map.json.
const SYNTH_KIND = {
  "recon:subfinder": "recon-map",
  "recon:httpx": "recon-map",
  "recon:nmap": "recon-map",
  "enum:nuclei": "enum-map",
  "enum:ffuf": "enum-map",
  "exploit:sqlmap": "exploit-map",
}

// --- shared helpers (all tolerant of garbage input, never throw) -----------

// True only when matchTarget itself resolves to ALLOW; any throw from a
// malformed scope/target is treated as DENY (fail-closed), never bubbled up
// -- this is the planner's own defense-in-depth pre-filter (spec §2.2);
// bh-exec re-checks the exact same matchTarget independently before it ever
// runs anything.
function isAllowed(target, scope) {
  try {
    return matchTarget(target, scope ?? {}).decision === "ALLOW"
  } catch {
    return false
  }
}

function dedupe(list) {
  const seen = new Set()
  const out = []
  for (const item of list) {
    if (seen.has(item)) continue
    seen.add(item)
    out.push(item)
  }
  return out
}

// The "root domain" behind each scope.in_scope.domains entry: a literal
// entry ("acme.io") is its own root; a wildcard entry ("*.acme.io") exists
// to clear discovered subdomains (per pentest-recon's *.<domain> rule) and
// its root is the apex with the "*." stripped. Deduped so a scope listing
// both "acme.io" and "*.acme.io" (the normal way to also allow subdomains)
// only ever produces one subfinder/httpx/nmap target for the apex itself.
function rootDomains(scope) {
  const domains = Array.isArray(scope?.in_scope?.domains) ? scope.in_scope.domains : []
  const roots = []
  for (const d of domains) {
    if (typeof d !== "string" || d.length === 0) continue
    roots.push(d.startsWith("*.") ? d.slice(2) : d)
  }
  return dedupe(roots)
}

function inScopeSubdomains(reconMap, scope) {
  const subdomains = Array.isArray(reconMap?.subdomains) ? reconMap.subdomains : []
  return subdomains.filter((s) => typeof s === "string" && s.length > 0 && isAllowed(s, scope))
}

// The host set recon:httpx probes and recon:nmap additionally draws on:
// every in-scope root, plus every discovered subdomain that clears scope.
// Roots first, then subdomains, deduped -- deterministic order.
function discoveredInScopeHosts(reconMap, scope) {
  return dedupe([...rootDomains(scope), ...inScopeSubdomains(reconMap, scope)])
}

// reconMap.http_services[] filtered down to just the (in-scope) urls -- the
// shared target list for enum:nuclei/enum:ffuf, and one of the two sources
// exploit:sqlmap draws candidate param-URLs from.
function liveHttpServiceUrls(reconMap, scope) {
  const services = Array.isArray(reconMap?.http_services) ? reconMap.http_services : []
  const urls = []
  for (const svc of services) {
    if (!svc || typeof svc !== "object") continue
    const url = svc.url
    if (typeof url !== "string" || url.length === 0) continue
    if (isAllowed(url, scope)) urls.push(url)
  }
  return urls
}

// The name of the first query-string parameter on a url, or null if it
// carries none. Tried via the URL constructor first (handles encoding
// correctly); falls back to a plain string split for anything the
// constructor rejects (e.g. a scheme-less/relative url) rather than
// throwing -- this module's tolerance policy applies here too.
function firstQueryParam(url) {
  try {
    const keys = [...new URL(url).searchParams.keys()]
    return keys.length > 0 ? keys[0] : null
  } catch {
    const qIndex = typeof url === "string" ? url.indexOf("?") : -1
    if (qIndex < 0) return null
    const first = url.slice(qIndex + 1).split("&")[0]
    const eq = first.indexOf("=")
    const name = eq >= 0 ? first.slice(0, eq) : first
    return name.length > 0 ? name : null
  }
}

// --- targetsForStage (spec §2.2) --------------------------------------------

// Pure planner: given the CURRENT maps + parsed scope, derive the bounded
// tool steps for exactly one stage. Every derived target is matchTarget-
// filtered to ALLOW only, in deterministic order. Never throws -- an unknown
// stage name, missing maps, or a broken scope all just yield [].
export function targetsForStage(stage, maps, scope) {
  try {
    const reconMap = maps?.reconMap
    const enumMap = maps?.enumMap

    switch (stage) {
      case "recon:subfinder": {
        return rootDomains(scope)
          .filter((domain) => isAllowed(domain, scope))
          .map((domain) => ({ tool: "subfinder", target: domain, flags: ["-silent", "-json"] }))
      }

      case "recon:httpx": {
        return discoveredInScopeHosts(reconMap, scope)
          .filter((host) => isAllowed(host, scope))
          .map((host) => ({
            tool: "httpx",
            target: `http://${host}`,
            flags: ["-silent", "-json", "-td", "-title", "-sc"],
          }))
      }

      case "recon:nmap": {
        const fromHosts = Array.isArray(reconMap?.hosts)
          ? reconMap.hosts.map((h) => h?.host).filter((h) => typeof h === "string" && h.length > 0)
          : []
        const merged = dedupe([...fromHosts, ...discoveredInScopeHosts(reconMap, scope)]).filter((h) => isAllowed(h, scope))
        return merged.map((host) => ({
          tool: "nmap",
          target: host,
          flags: ["-sT", "-Pn", "-T3", "-p", "80,443,22,8080,8443", "-oG", "-"],
        }))
      }

      case "enum:nuclei": {
        return liveHttpServiceUrls(reconMap, scope).map((url) => ({
          tool: "nuclei",
          target: url,
          flags: ["-silent", "-jsonl", "-disable-update-check", "-severity", "info,low,medium,high,critical", "-c", "25", "-rl", "150"],
        }))
      }

      case "enum:ffuf": {
        return liveHttpServiceUrls(reconMap, scope).map((url) => ({
          tool: "ffuf",
          target: `${url}/FUZZ`,
          flags: ["-w", "/usr/share/boundhound/wordlists/common.txt", "-mc", "200,204,301,302,401,403", "-t", "40", "-o", "/dev/stdout", "-of", "json", "-s"],
        }))
      }

      case "exploit:sqlmap": {
        const reconUrls = Array.isArray(reconMap?.http_services)
          ? reconMap.http_services.map((s) => s?.url).filter((u) => typeof u === "string" && u.length > 0)
          : []
        const enumUrls = Array.isArray(enumMap?.content)
          ? enumMap.content.map((c) => c?.url).filter((u) => typeof u === "string" && u.length > 0)
          : []
        const candidates = dedupe([...reconUrls, ...enumUrls])

        const steps = []
        for (const url of candidates) {
          const param = firstQueryParam(url)
          if (!param) continue // no query param -> nothing to test, no step
          if (!isAllowed(url, scope)) continue
          steps.push({ tool: "sqlmap", target: url, flags: ["--batch", "--level", "1", "--risk", "1", "--dbs", "-p", param] })
        }
        return steps
      }

      default:
        return []
    }
  } catch {
    return []
  }
}

// --- runFullscan (spec §2.3) -------------------------------------------------

function errMessage(err) {
  return err && err.message ? err.message : String(err)
}

// Classifies a runner's resolved return value into the outcome vocabulary
// resume/retry key off. A throw is classified by the caller (always
// "transient", per spec §3) -- this only handles what the runner RETURNS:
// today's void/undefined runner (and any object with no string `status`,
// e.g. the old `{ok:true}` shape some mocks used) -> "ok"; an explicit
// `{status}` -> that status verbatim. This is the entire backward-compat
// seam: nothing here can turn a today-shaped return into anything other
// than "ok".
function classifyResult(result) {
  if (result && typeof result === "object" && typeof result.status === "string") return result.status
  return "ok"
}

// Injectable staged driver: sequences the fixed stage order, deriving each
// stage's steps fresh from `loadMaps()` + `scope`, running each through
// `runner`, then rebuilding the relevant map via `synth`. Finishes with
// `synth("findings")` then `synth("report")`. NEVER throws overall -- every
// per-step/per-stage failure (a throwing runner, a throwing synth/loadMaps)
// is caught, logged via `log`, and treated as skipped, not fatal.
//
// Phase 7 resilience (spec §3) layers three OPTIONAL, independently-off-by-
// default behaviors on top of the Phase 6 shape above, none of which change
// a single observable behavior when the caller passes none of them:
//   - resume: `loadState`/`saveState` + `stepKey`/`isDone`/`markDone` (Task
//     1's pure model) let an interrupted scan skip already-completed steps
//     on a later run. Off (`resume` falsy) means `loadState`/`saveState` are
//     NEVER called and every step is treated as not-done, i.e. today.
//   - retry: a runner outcome classified "transient" (a throw, or an
//     explicit `{status:"transient"}`) is retried up to `retry.maxRetries`
//     times with an injected `sleep(retry.backoff(attempt))` between
//     attempts; `maxRetries` defaults to 0, i.e. today's single attempt.
//     "denied" and "ok" are terminal outcomes and are never retried.
//   - budget: an optional hard ceiling (`maxSteps` across the whole run,
//     `maxStepsPerStage` per stage) on how many steps are actually RUN
//     (never on resumed-skips). Reaching `maxSteps` stops all further
//     planning/running immediately (findings+report still run at the end);
//     reaching `maxStepsPerStage` just moves on to the next stage.
export async function runFullscan(deps = {}, opts = {}) {
  const { runner, synth, loadMaps, scope } = deps ?? {}
  const doLog = typeof deps?.log === "function" ? deps.log : () => {}
  const doRunner = typeof runner === "function" ? runner : async () => {}
  const doSynth = typeof synth === "function" ? synth : async () => {}
  const doLoadMaps = typeof loadMaps === "function" ? loadMaps : () => ({})
  const doLoadState = typeof deps?.loadState === "function" ? deps.loadState : async () => emptyState()
  const doSaveState = typeof deps?.saveState === "function" ? deps.saveState : async () => {}
  const doSleep = typeof deps?.sleep === "function" ? deps.sleep : async () => {}
  const exploit = opts?.exploit
  const resume = Boolean(opts?.resume)
  const maxRetries = typeof opts?.retry?.maxRetries === "number" ? opts.retry.maxRetries : 0
  const backoff = typeof opts?.retry?.backoff === "function" ? opts.retry.backoff : () => 0
  const budget = opts?.budget

  const summary = { stages: [], reportGenerated: false, toolsRun: 0, resumedSkipped: 0, retried: 0, budgetStopped: false }

  // Loaded once, up front, ONLY when resuming -- per spec §3, a non-resume
  // run never touches loadState/saveState at all, matching today exactly.
  let state = emptyState()
  if (resume) {
    try {
      state = (await doLoadState()) ?? emptyState()
    } catch (err) {
      doLog(`resume: loadState failed, starting fresh: ${errMessage(err)}`)
      state = emptyState()
    }
  }

  let stepsRun = 0 // budget.maxSteps counter -- steps actually RUN this invocation, never resumed-skips

  try {
    const stages = STAGE_ORDER.filter((stage) => exploit !== false || stage !== "exploit:sqlmap")

    outerStages: for (const stage of stages) {
      // Checked at the top of every stage too (not just mid-stage below) so
      // that once the run budget is exhausted, later stages are never even
      // planned (loadMaps/targetsForStage skipped entirely for them).
      if (typeof budget?.maxSteps === "number" && stepsRun >= budget.maxSteps) {
        doLog(`budget: maxSteps reached, stopping further stages`)
        summary.budgetStopped = "maxSteps"
        break outerStages
      }

      let maps = {}
      try {
        maps = (await doLoadMaps()) ?? {}
      } catch (err) {
        doLog(`stage ${stage}: loadMaps failed, treating as empty maps: ${errMessage(err)}`)
      }

      let steps = []
      try {
        steps = targetsForStage(stage, maps, scope) ?? []
      } catch (err) {
        doLog(`stage ${stage}: planning failed, treating as no targets: ${errMessage(err)}`)
      }

      if (steps.length === 0) {
        doLog(`stage ${stage}: no targets, skipping`)
        summary.stages.push({ stage, steps: 0 })
        continue
      }

      doLog(`stage ${stage}: running ${steps.length} step(s)`)
      let stepsThisStage = 0
      for (const step of steps) {
        const key = resume ? stepKey({ stage, tool: step.tool, target: step.target }) : null

        if (resume && isDone(state, key)) {
          doLog(`resume: skip ${key}`)
          summary.resumedSkipped++
          continue
        }

        if (typeof budget?.maxStepsPerStage === "number" && stepsThisStage >= budget.maxStepsPerStage) {
          doLog(`budget: maxStepsPerStage reached for stage ${stage}, moving to next stage`)
          break
        }
        if (typeof budget?.maxSteps === "number" && stepsRun >= budget.maxSteps) {
          // Do NOT break outerStages here: steps already run THIS stage may
          // have written real output that only this stage's own synth turns
          // into recon-map/enum-map/exploit-map.json (which findings/report
          // read). Break only the per-step loop so the code below still
          // records this (interrupted) stage's summary entry and runs its
          // synth -- the run-wide stop happens right after that, once this
          // stage is fully accounted for.
          doLog(`budget: maxSteps reached mid-stage ${stage}, finishing this stage's synth before stopping`)
          summary.budgetStopped = "maxSteps"
          break
        }

        summary.toolsRun++
        stepsRun++
        stepsThisStage++

        // Bounded retry: only a "transient" outcome loops back; "ok" and
        // "denied" are both terminal on the first classification. A throw
        // from the runner is ALWAYS "transient" (never "denied") -- this is
        // what keeps today's throwing-runner behavior identical when
        // maxRetries is 0 (its only default).
        let outcome = "ok"
        let lastMessage = null
        let retriesUsed = 0
        for (;;) {
          try {
            const result = await doRunner({ ...step, stage })
            outcome = classifyResult(result)
            lastMessage = null
          } catch (err) {
            outcome = "transient"
            lastMessage = errMessage(err)
          }

          if (outcome !== "transient") break
          if (retriesUsed >= maxRetries) break
          doLog(
            `stage ${stage}: step ${step.tool} ${step.target} transient (attempt ${retriesUsed + 1}/${maxRetries}), retrying: ${lastMessage}`
          )
          await doSleep(backoff(retriesUsed))
          retriesUsed++
        }
        summary.retried += retriesUsed

        if (outcome === "transient") {
          doLog(`stage ${stage}: step ${step.tool} ${step.target} failed/denied, skipping: ${lastMessage ?? "transient failure"}`)
        } else if (outcome === "denied") {
          doLog(`stage ${stage}: step ${step.tool} ${step.target} denied, skipping`)
        }

        // ok and denied are both SETTLED outcomes -- a denied step is not
        // going to succeed on a later resume either, so it's marked done
        // too (only an exhausted "transient" is left for a later --resume
        // to retry).
        if (resume && (outcome === "ok" || outcome === "denied")) {
          state = markDone(state, key)
          try {
            await doSaveState(state)
          } catch (err) {
            doLog(`resume: saveState failed: ${errMessage(err)}`)
          }
        }
      }
      summary.stages.push({ stage, steps: steps.length })

      try {
        await doSynth(SYNTH_KIND[stage])
      } catch (err) {
        doLog(`stage ${stage}: synth(${SYNTH_KIND[stage]}) failed: ${errMessage(err)}`)
      }

      // The interrupted stage (if any) is now fully accounted for -- its
      // summary entry is pushed and its synth ran above -- so it's now safe
      // to stop the whole run.
      if (summary.budgetStopped) break outerStages
    }

    try {
      await doSynth("findings")
    } catch (err) {
      doLog(`synth(findings) failed: ${errMessage(err)}`)
    }
    try {
      await doSynth("report")
    } catch (err) {
      doLog(`synth(report) failed: ${errMessage(err)}`)
    }
    summary.reportGenerated = true
  } catch (err) {
    doLog(`runFullscan: unexpected error, stopping: ${errMessage(err)}`)
  }

  return summary
}
