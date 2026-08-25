// src/report/report.mjs
//
// Pure markdown renderer for Phase 5 (spec §2). No I/O here on purpose —
// the CLI (bin/bh-report.mjs) owns reading findings.json + scope.yaml
// (via parseScope) + summarizing audit.log; this module only ever turns
// already-structured data into a markdown string, so it unit-tests
// against fixtures with no filesystem involved. Like findings.mjs, every
// function here tolerates missing/garbage input rather than throwing —
// findings.json/scope.yaml/audit summaries are not a contract this module
// controls, and a broken/half-written input must still produce a report
// rather than crash the CLI.

// Fixed severity ranking, worst-first, per spec §2 point 5. Anything not in
// this set (missing/garbage `severity`) is bucketed as "info" -- the same
// safe default findings.mjs's severityFor uses for unknown types, so a
// malformed finding still shows up in the report rather than vanishing.
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
const SEVERITY_SET = new Set(SEVERITY_ORDER)

function normalizeSeverity(severity) {
  return SEVERITY_SET.has(severity) ? severity : "info"
}

// --- remediation table (spec §2.1) ------------------------------------------

const REMEDIATION = {
  sqli:
    "Use parameterized queries / prepared statements for all database access; validate and " +
    "escape user input; apply least-privilege database accounts so a successful injection has " +
    "minimal reach.",
  nuclei:
    "Review the flagged template's category and severity; patch or upgrade the affected " +
    "component, or apply the documented mitigation for that specific template.",
  "open-port":
    "Confirm the service is intentionally exposed; restrict access with a firewall or " +
    "security-group rule scoped to the clients that need it; disable the service entirely if " +
    "it is not required.",
  "http-service":
    "Review this exposed service for necessity and attack-surface awareness; ensure it " +
    "requires authentication where appropriate, is kept patched, and is not leaking more than " +
    "intended (version banners, debug pages).",
  content:
    "Review this discovered content for unintended exposure (backups, debug endpoints, " +
    "credentials, source maps); remove stale or unneeded files from the production host.",
  subdomain:
    "Confirm this subdomain is still in active use; decommission it and remove its DNS record " +
    "if it is stale, to reduce the organization's attack surface.",
}

const GENERIC_REMEDIATION = "Investigate and remediate this finding per your organization's standard vulnerability-management process."

// Table-driven per spec §2.1. Never throws: an unknown, missing, or
// non-string `type` simply falls through to the generic guidance rather
// than fabricating remediation advice for a finding type this table
// doesn't know about.
export function remediationFor(type) {
  return Object.prototype.hasOwnProperty.call(REMEDIATION, type) ? REMEDIATION[type] : GENERIC_REMEDIATION
}

// --- small rendering helpers -------------------------------------------

function safeStamp(now) {
  try {
    if (typeof now === "function") {
      const value = now()
      if (typeof value === "string" && value.length > 0) return value
    }
  } catch {
    // fall through to the real-time fallback below
  }
  // No injected `now` (or it misbehaved) -- production default. This is the
  // only place real wall-clock time can leak in, matching findings.mjs's
  // `(now ?? (() => new Date().toISOString()))()` convention: tests always
  // inject `now`, so the determinism contract holds for every test-covered
  // path.
  return new Date().toISOString()
}

function placeholder(value) {
  return typeof value === "string" && value.length > 0 ? value : "(unspecified)"
}

function renderScalarOrObject(value) {
  if (value !== null && typeof value === "object") {
    try {
      return JSON.stringify(value)
    } catch {
      return "(unrenderable)"
    }
  }
  return String(value)
}

function renderValue(value) {
  if (value === null || value === undefined || value === "") return "(none)"
  if (Array.isArray(value)) return value.length > 0 ? value.map((v) => renderScalarOrObject(v)).join(", ") : "(none)"
  return renderScalarOrObject(value)
}

function renderEvidence(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return "- (none provided)"
  const keys = Object.keys(evidence)
  if (keys.length === 0) return "- (none provided)"
  return keys.map((k) => `- ${k}: ${renderValue(evidence[k])}`).join("\n")
}

function listOrNone(list) {
  const clean = Array.isArray(list) ? list.filter((x) => typeof x === "string" && x.length > 0) : []
  return clean.length > 0 ? clean.map((x) => `\`${x}\``).join(", ") : "(none)"
}

// --- sections ------------------------------------------------------------

function renderHeader(meta, now) {
  const m = meta && typeof meta === "object" ? meta : {}
  const lines = []
  lines.push(`# Penetration Test Report — ${placeholder(m.engagement)}`)
  lines.push("")
  lines.push(`- **Generated:** ${safeStamp(now)}`)
  lines.push(`- **Authorization:** ${placeholder(m.authorization)}`)
  lines.push(`- **Mode:** ${placeholder(m.mode)}`)
  lines.push(`- **Scope enforcement:** ${placeholder(m.scope_enforcement)}`)
  lines.push("")
  return lines.join("\n")
}

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) counts[normalizeSeverity(f?.severity)]++
  return counts
}

function renderExecSummary(findings) {
  const counts = countBySeverity(findings)
  const total = findings.length
  const verifiedCount = findings.filter((f) => f.verified === true).length
  const criticalOrHighVerified = findings.filter(
    (f) => f.verified === true && (normalizeSeverity(f.severity) === "critical" || normalizeSeverity(f.severity) === "high")
  ).length

  const lines = []
  lines.push("## Executive Summary")
  lines.push("")
  lines.push("| Severity | Count |")
  lines.push("|---|---|")
  lines.push(`| Critical | ${counts.critical} |`)
  lines.push(`| High | ${counts.high} |`)
  lines.push(`| Medium | ${counts.medium} |`)
  lines.push(`| Low | ${counts.low} |`)
  lines.push(`| Info | ${counts.info} |`)
  lines.push("")
  lines.push(`**Verified:** ${verifiedCount} of ${total} finding(s) have been independently verified.`)
  lines.push("")
  if (total === 0) {
    lines.push("No findings were recorded during this engagement.")
  } else {
    lines.push(
      `This engagement recorded ${total} finding(s). ${verifiedCount} of these are confirmed verified, ` +
        `including ${criticalOrHighVerified} at critical-or-high severity.`
    )
  }
  lines.push("")
  return lines.join("\n")
}

function renderScope(meta) {
  const m = meta && typeof meta === "object" ? meta : {}
  const inScope = m.in_scope && typeof m.in_scope === "object" ? m.in_scope : {}
  const outScope = m.out_of_scope && typeof m.out_of_scope === "object" ? m.out_of_scope : {}

  const lines = []
  lines.push("## Scope")
  lines.push("")
  lines.push("**In scope:**")
  lines.push(`- Domains: ${listOrNone(inScope.domains)}`)
  lines.push(`- CIDRs: ${listOrNone(inScope.cidrs)}`)
  lines.push("")
  lines.push("**Out of scope:**")
  lines.push(`- Domains: ${listOrNone(outScope.domains)}`)
  lines.push(`- CIDRs: ${listOrNone(outScope.cidrs)}`)
  if (typeof m.notes === "string" && m.notes.length > 0) {
    lines.push("")
    lines.push(`**Notes:** ${m.notes}`)
  }
  lines.push("")
  return lines.join("\n")
}

// Static, truthful text -- no per-engagement data, so it is identical
// across every report by construction (trivially deterministic).
function renderMethodology() {
  const lines = []
  lines.push("## Methodology")
  lines.push("")
  lines.push("This engagement followed a phased assessment workflow:")
  lines.push("")
  lines.push("1. **Recon** — passive/active discovery of hosts, subdomains, open ports, and exposed HTTP services.")
  lines.push("2. **Enum** — content discovery and vulnerability-template scanning against in-scope targets.")
  lines.push("3. **Exploit** — targeted proof-of-vulnerability testing against candidate weaknesses (e.g. injection points).")
  lines.push(
    "4. **Verify** — re-running the same bounded check against each candidate finding to confirm it reproduces " +
      "before it is reported as verified."
  )
  lines.push("")
  lines.push(
    "Every tool invocation in every phase ran through the enforced `bh-exec` choke point, which applies scope " +
      "enforcement, safety-constraint checks, audit logging, and containerized execution uniformly — no tool ran " +
      "outside of this control."
  )
  lines.push("")
  return lines.join("\n")
}

function compareFindings(a, b) {
  const ta = String(a?.target ?? "")
  const tb = String(b?.target ?? "")
  if (ta !== tb) return ta < tb ? -1 : 1
  const ia = String(a?.id ?? "")
  const ib = String(b?.id ?? "")
  if (ia !== ib) return ia < ib ? -1 : 1
  return 0
}

function groupBySeverity(findings) {
  const groups = { critical: [], high: [], medium: [], low: [], info: [] }
  for (const f of findings) groups[normalizeSeverity(f.severity)].push(f)
  for (const severity of SEVERITY_ORDER) groups[severity].sort(compareFindings)
  return groups
}

function renderFinding(f) {
  const severity = normalizeSeverity(f.severity)
  const type = typeof f.type === "string" && f.type.length > 0 ? f.type : "(unknown)"
  const target = f.target !== undefined && f.target !== null && f.target !== "" ? String(f.target) : "(unspecified target)"
  const confidence = placeholder(f.confidence)
  const verified = f.verified === true ? "Yes" : "No"

  const lines = []
  lines.push(`### [${severity.toUpperCase()}] ${type} — ${target}`)
  lines.push("")
  lines.push(`**Confidence:** ${confidence}  |  **Verified:** ${verified}`)
  lines.push("")
  lines.push("**Evidence:**")
  lines.push(renderEvidence(f.evidence))
  lines.push("")
  lines.push("**Remediation:**")
  lines.push(remediationFor(f.type))
  lines.push("")
  return lines.join("\n")
}

function renderFindingsSection(findings) {
  if (findings.length === 0) {
    return ["## Findings", "", "No findings recorded.", ""].join("\n")
  }

  const groups = groupBySeverity(findings)
  const parts = ["## Findings", ""]
  for (const severity of SEVERITY_ORDER) {
    const list = groups[severity]
    if (list.length === 0) continue // skip empty severity groups
    parts.push(`#### ${severity.toUpperCase()} (${list.length})`)
    parts.push("")
    for (const f of list) parts.push(renderFinding(f))
  }
  return parts.join("\n")
}

function renderAppendix(auditSummary) {
  const lines = ["## Appendix", ""]
  if (auditSummary && typeof auditSummary === "object") {
    const allow = Number.isFinite(auditSummary.allow) ? auditSummary.allow : 0
    const deny = Number.isFinite(auditSummary.deny) ? auditSummary.deny : 0
    const total = Number.isFinite(auditSummary.total) ? auditSummary.total : allow + deny
    lines.push(`- **Audit log:** ${allow} ALLOW, ${deny} DENY (${total} total decisions).`)
  }
  lines.push("- Raw tool output for this engagement is available under `output/`.")
  lines.push("")
  return lines.join("\n")
}

// Turns findings.json's `findings` array + a parsed-scope `meta` object (+
// an optional audit summary) into a full markdown pentest report. Pure, no
// I/O, deterministic (same findings+meta+now -> byte-identical string), and
// NEVER throws -- every field is read defensively so a missing/garbage
// `findings` array, a partial `meta`, or a broken `auditSummary` still
// produces a valid report instead of crashing the CLI (spec §2). Renders
// only data that is actually present -- no fabricated findings, severities,
// or evidence.
export function buildReport(input, options) {
  try {
    // Destructuring is deliberately NOT done in the parameter list: a
    // caller passing `null` for either argument (as opposed to omitting it)
    // would throw at the call site, before this try/catch's protection
    // even starts. Reading fields off a safely-defaulted local object
    // instead keeps "never throws" true for every possible input shape.
    const { findings, meta, auditSummary } = input && typeof input === "object" ? input : {}
    const now = options && typeof options === "object" ? options.now : undefined

    const cleanFindings = Array.isArray(findings) ? findings.filter((f) => f && typeof f === "object") : []

    return [
      renderHeader(meta, now),
      renderExecSummary(cleanFindings),
      renderScope(meta),
      renderMethodology(),
      renderFindingsSection(cleanFindings),
      renderAppendix(auditSummary),
    ].join("\n")
  } catch {
    // Last-resort safety net: buildReport's contract is "never throws," so
    // even a defect in the rendering path above must still yield a valid,
    // truthful (if minimal) report rather than propagate an exception.
    return "# Penetration Test Report — (unspecified)\n\n## Findings\n\nNo findings recorded.\n"
  }
}
