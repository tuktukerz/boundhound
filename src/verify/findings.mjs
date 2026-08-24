// src/verify/findings.mjs
//
// Pure consolidation + re-verification layer for Phase 4. No I/O here on
// purpose (spec §2) — the CLI (bin/bh-findings.mjs) owns reading
// recon-map.json/enum-map.json/exploit-map.json + verify/recheck outputs and
// writing findings.json; these functions only ever see structured maps in,
// structured findings out, so they unit-test against fixtures with no
// filesystem involved. Like recon-map/enum-map/exploit-map, every function
// here tolerates missing/garbage input rather than throwing — the upstream
// maps are not a contract this module controls.

// FNV-1a, 32-bit, over a plain string. Chosen over Node's `crypto` module
// deliberately: `crypto.createHash` is available but pulls in a whole hash
// algorithm (and its randomness-adjacent API surface) for a job that only
// needs a short, stable, collision-unlikely-enough fingerprint of a finding
// key — not a cryptographic guarantee. FNV-1a is ~10 lines, has no
// dependency, and — critically for spec §2's "no time/random in the id"
// requirement — is a pure function of its input string: same string in,
// same digest out, forever. `>>> 0` folds the signed 32-bit result from
// Math.imul into an unsigned int before hex-encoding it.
function fnv1aHex(str) {
  let hash = 0x811c9dc5
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193)
  }
  return (hash >>> 0).toString(16).padStart(8, "0")
}

// The stable id is a hash of "category|type|target|key" (spec §2.2) — key is
// whatever sub-field disambiguates multiple findings that would otherwise
// share the same category+type+target (a port number, a template_id, a
// ffuf path, the literal "sqli"). String()-coerce target/key so `null`,
// numbers, etc. all hash predictably instead of via implicit `${}` coercion
// surprises (e.g. template literals already do this, but being explicit
// documents the intent).
function makeId(category, type, target, key) {
  return fnv1aHex(`${category}|${type}|${String(target)}|${String(key)}`)
}

// Every severity name buildFindings/severityFor can ever produce, ranked
// low-to-high so dedup can pick "the highest severity" with a plain number
// comparison instead of a chain of if/else.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

// Table-driven per spec §2: recon/enum "observation" types are always
// info (an open port or a discovered path isn't itself a graded severity);
// nuclei carries the severity nuclei itself assigned; sqli is always high
// (a confirmed injection is never "info"). Anything else (unknown type, or
// nuclei with a missing/garbage sourceSeverity) safely defaults to "info"
// rather than throwing or producing an invalid severity string.
export function severityFor(type, sourceSeverity) {
  switch (type) {
    case "open-port":
    case "http-service":
    case "subdomain":
    case "content":
      return "info"
    case "nuclei": {
      const s = typeof sourceSeverity === "string" ? sourceSeverity.toLowerCase() : ""
      return Object.prototype.hasOwnProperty.call(SEVERITY_RANK, s) ? s : "info"
    }
    case "sqli":
      return "high"
    default:
      return "info"
  }
}

// --- per-source normalization (spec §2.2) -----------------------------------

function reconFindings(reconMap) {
  const findings = []

  const hosts = Array.isArray(reconMap?.hosts) ? reconMap.hosts : []
  for (const h of hosts) {
    if (!h || typeof h !== "object") continue
    const host = h.host ?? null
    const ports = Array.isArray(h.ports) ? h.ports : []
    for (const p of ports) {
      if (!p || typeof p !== "object") continue
      const port = p.port ?? null
      findings.push({
        id: makeId("recon", "open-port", host, port),
        category: "recon",
        type: "open-port",
        target: host,
        severity: severityFor("open-port"),
        confidence: "reported",
        evidence: { port, proto: p.proto ?? null, service: p.service ?? null },
        verified: false,
      })
    }
  }

  const httpServices = Array.isArray(reconMap?.http_services) ? reconMap.http_services : []
  for (const s of httpServices) {
    if (!s || typeof s !== "object") continue
    const target = s.url ?? null
    findings.push({
      id: makeId("recon", "http-service", target, ""),
      category: "recon",
      type: "http-service",
      target,
      severity: severityFor("http-service"),
      confidence: "reported",
      evidence: { status_code: s.status_code ?? null, title: s.title ?? null, tech: s.tech ?? [] },
      verified: false,
    })
  }

  const subdomains = Array.isArray(reconMap?.subdomains) ? reconMap.subdomains : []
  for (const name of subdomains) {
    if (typeof name !== "string" || name.length === 0) continue
    findings.push({
      id: makeId("recon", "subdomain", name, ""),
      category: "recon",
      type: "subdomain",
      target: name,
      severity: severityFor("subdomain"),
      confidence: "reported",
      evidence: {},
      verified: false,
    })
  }

  return findings
}

function enumFindings(enumMap) {
  const findings = []

  const nuclei = Array.isArray(enumMap?.findings) ? enumMap.findings : []
  for (const f of nuclei) {
    if (!f || typeof f !== "object") continue
    const target = f.host ?? null
    const templateId = f.template_id ?? null
    findings.push({
      id: makeId("enum", "nuclei", target, templateId),
      category: "enum",
      type: "nuclei",
      target,
      severity: severityFor("nuclei", f.severity),
      confidence: "reported",
      evidence: { template_id: templateId, name: f.name ?? null, matched_at: f.matched_at ?? null },
      verified: false,
    })
  }

  const content = Array.isArray(enumMap?.content) ? enumMap.content : []
  for (const c of content) {
    if (!c || typeof c !== "object") continue
    const target = c.url ?? null
    const path = c.path ?? null
    findings.push({
      id: makeId("enum", "content", target, path),
      category: "enum",
      type: "content",
      target,
      severity: severityFor("content"),
      confidence: "reported",
      evidence: { path, status: c.status ?? null, length: c.length ?? null },
      verified: false,
    })
  }

  return findings
}

function exploitFindings(exploitMap) {
  const findings = []

  const entries = Array.isArray(exploitMap?.findings) ? exploitMap.findings : []
  for (const e of entries) {
    if (!e || typeof e !== "object") continue
    // vulnerable:false (or anything not literally true) -> no finding at
    // all, per spec §2.2 -- sqlmap said "not injectable", there is nothing
    // to report.
    if (e.vulnerable !== true) continue
    const target = e.target ?? null
    findings.push({
      id: makeId("exploit", "sqli", target, "sqli"),
      category: "exploit",
      type: "sqli",
      target,
      severity: severityFor("sqli"),
      // sqlmap already confirmed the injection by exploiting it -- there is
      // no weaker "reported" state for this category, unlike recon/enum.
      confidence: "confirmed",
      evidence: { dbms: e.dbms ?? null, injection_points: Array.isArray(e.injection_points) ? e.injection_points : [] },
      verified: true,
    })
  }

  return findings
}

// Findings sharing an id are the "same" finding observed twice (e.g. two
// enum runs both reporting the same nuclei template on the same host).
// Keep the highest severity seen, OR the evidence together (later values
// win on key collision, arbitrarily but deterministically, since object
// spread order follows insertion order), and treat "verified"/"confirmed"
// as sticky -- once any duplicate has been verified/confirmed, the merged
// finding stays that way.
function dedupe(findings) {
  const byId = new Map()
  for (const f of findings) {
    const prior = byId.get(f.id)
    if (!prior) {
      byId.set(f.id, f)
      continue
    }
    const priorRank = SEVERITY_RANK[prior.severity] ?? 0
    const nextRank = SEVERITY_RANK[f.severity] ?? 0
    const base = nextRank > priorRank ? f : prior
    byId.set(f.id, {
      ...base,
      evidence: { ...prior.evidence, ...f.evidence },
      verified: prior.verified || f.verified,
      confidence: prior.confidence === "confirmed" || f.confidence === "confirmed" ? "confirmed" : base.confidence,
    })
  }
  return [...byId.values()]
}

// Consolidates recon-map + enum-map + exploit-map (spec §2.1/§2.2) into one
// normalized, severity-scored, de-duplicated findings list. Pure: never
// touches the filesystem/network, never throws -- a garbage or missing map
// just contributes zero findings from that source. `now` is injected (like
// buildReconMap/buildEnumMap/buildExploitMap) so production gets a real
// timestamp while tests stay deterministic.
export function buildFindings({ reconMap, enumMap, exploitMap } = {}, { now } = {}) {
  const stamp = (now ?? (() => new Date().toISOString()))()
  const all = [...reconFindings(reconMap), ...enumFindings(enumMap), ...exploitFindings(exploitMap)]
  return { generated_at: stamp, findings: dedupe(all) }
}

// Extracts the same per-type "key" that went into a finding's id, so a
// recheck result expressed as {type, target, key} (rather than a raw id)
// can be matched against a finding without the caller needing to know this
// module's hashing scheme. Types with no disambiguating sub-field
// (http-service, subdomain) have no key -- there is nothing to extract.
function findingKey(finding) {
  switch (finding?.type) {
    case "open-port":
      return finding.evidence?.port
    case "content":
      return finding.evidence?.path
    case "nuclei":
      return finding.evidence?.template_id
    case "sqli":
      return "sqli"
    default:
      return undefined
  }
}

// A recheck result matches a finding either by exact `id`, or by
// `type`+`target` (further narrowed by `key` when the recheck result
// supplies one -- e.g. distinguishing port 80 from port 22 on the same
// host). Matching by id is preferred when present since it's unambiguous;
// the type/target/key path exists for callers (the pentest-verify skill)
// that re-derive a recheck outcome from a fresh tool run without carrying
// the original finding object around.
function matchesRecheck(finding, recheck) {
  if (!recheck || typeof recheck !== "object") return false

  if (typeof recheck.id === "string" && recheck.id.length > 0) {
    return finding.id === recheck.id
  }

  if (recheck.type !== finding.type) return false
  if (recheck.target !== finding.target) return false
  if (recheck.key !== undefined && recheck.key !== null) {
    return String(recheck.key) === String(findingKey(finding))
  }
  return true
}

// Applies re-verification outcomes (spec §2.3) to a findings list. Returns
// a NEW array of NEW finding objects -- the input is never mutated, so a
// caller can safely diff before/after. A finding with a matching
// `reproduced:true` recheck result flips to verified:true/confidence:
// "confirmed"; `reproduced:false` (or no matching recheck at all) leaves
// the finding exactly as it was -- re-verification only ever adds
// confidence, it never removes a finding or downgrades it back to
// unverified.
export function applyVerification(findings, recheckResults) {
  const list = Array.isArray(findings) ? findings : []
  const rechecks = Array.isArray(recheckResults) ? recheckResults : []

  return list.map((f) => {
    if (!f || typeof f !== "object") return f
    const reproduced = rechecks.some((r) => r?.reproduced === true && matchesRecheck(f, r))
    if (!reproduced) return { ...f }
    return { ...f, verified: true, confidence: "confirmed" }
  })
}
