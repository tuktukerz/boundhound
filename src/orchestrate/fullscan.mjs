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
        return discoveredInScopeHosts(reconMap, scope).map((host) => ({
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

// Injectable staged driver: sequences the fixed stage order, deriving each
// stage's steps fresh from `loadMaps()` + `scope`, running each through
// `runner`, then rebuilding the relevant map via `synth`. Finishes with
// `synth("findings")` then `synth("report")`. NEVER throws overall -- every
// per-step/per-stage failure (a throwing runner, a throwing synth/loadMaps)
// is caught, logged via `log`, and treated as skipped, not fatal.
export async function runFullscan(deps = {}, opts = {}) {
  const { runner, synth, loadMaps, scope } = deps ?? {}
  const doLog = typeof deps?.log === "function" ? deps.log : () => {}
  const doRunner = typeof runner === "function" ? runner : async () => {}
  const doSynth = typeof synth === "function" ? synth : async () => {}
  const doLoadMaps = typeof loadMaps === "function" ? loadMaps : () => ({})
  const exploit = opts?.exploit

  const summary = { stages: [], reportGenerated: false, toolsRun: 0 }

  try {
    const stages = STAGE_ORDER.filter((stage) => exploit !== false || stage !== "exploit:sqlmap")

    for (const stage of stages) {
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
      for (const step of steps) {
        summary.toolsRun++
        try {
          await doRunner({ ...step, stage })
        } catch (err) {
          doLog(`stage ${stage}: step ${step.tool} ${step.target} failed/denied, skipping: ${errMessage(err)}`)
        }
      }
      summary.stages.push({ stage, steps: steps.length })

      try {
        await doSynth(SYNTH_KIND[stage])
      } catch (err) {
        doLog(`stage ${stage}: synth(${SYNTH_KIND[stage]}) failed: ${errMessage(err)}`)
      }
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
