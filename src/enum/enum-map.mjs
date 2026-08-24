// src/enum/enum-map.mjs
//
// Pure parsers + synthesizer for Phase 2 enum output. No I/O here on
// purpose (spec §2.3) — the CLI (bin/bh-enum-map.mjs) owns reading the raw
// tool output files and writing enum-map.json; these functions only ever
// see text in, structured data out, so they unit-test against fixtures with
// no filesystem involved.

// ffuf's `-of json` output is ONE JSON object with a top-level `results`
// array (not line-oriented like the recon tools) — see
// pkg/output/file_json.go in ffuf's source: each result carries
// `input: { "<keyword>": "<value>" }` (the FUZZ placeholder's value),
// `url`, `status`, `length`, `words`, `host`. Blank text or invalid JSON
// returns [] rather than throwing — same tolerance policy as recon-map's
// parsers, since tool output is not a contract we control. A missing or
// non-array `results` field is likewise treated as no results.
export function parseFfufJson(text) {
  if (!text) return []
  let obj
  try {
    obj = JSON.parse(text)
  } catch {
    return []
  }
  if (!obj || typeof obj !== "object" || !Array.isArray(obj.results)) return []
  return obj.results.map((r) => ({
    url: r?.url ?? null,
    path: r?.input && typeof r.input === "object" ? r.input.FUZZ ?? null : null,
    status: r?.status ?? null,
    length: r?.length ?? null,
    words: r?.words ?? null,
    host: r?.host ?? null,
  }))
}

// nuclei's `-jsonl` output is one JSON object per line, same shape as
// recon-map's JSONL parsers: blank lines and lines that fail JSON.parse (or
// aren't an object) are skipped rather than thrown on.
export function parseNucleiJsonl(text) {
  const findings = []
  for (const rawLine of (text ?? "").split("\n")) {
    const line = rawLine.trim()
    if (!line) continue
    let obj
    try {
      obj = JSON.parse(line)
    } catch {
      continue
    }
    if (!obj || typeof obj !== "object") continue
    findings.push({
      template_id: obj["template-id"] ?? null,
      name: obj.info?.name ?? null,
      severity: obj.info?.severity ?? null,
      host: obj.host ?? null,
      matched_at: obj["matched-at"] ?? null,
      type: obj.type ?? null,
    })
  }
  return findings
}

// Every severity bucket is always present, defaulted to 0 — a consumer of
// enum-map.json can always read by_severity.high without an existence
// check, even on an engagement with zero findings so far.
const SEVERITIES = ["info", "low", "medium", "high", "critical"]

function countBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]))
  for (const f of findings) {
    if (Object.prototype.hasOwnProperty.call(counts, f.severity)) counts[f.severity]++
  }
  return counts
}

// Merges the two raw tool outputs into one normalized enum-map object.
// generated_at comes from an injected `now` (defaulted here, not at the call
// site) so callers get a real timestamp in production while tests stay
// deterministic by injecting their own.
export function buildEnumMap({ ffufJson, nucleiJsonl } = {}, { now } = {}) {
  const stamp = (now ?? (() => new Date().toISOString()))()
  const findings = parseNucleiJsonl(nucleiJsonl ?? "")
  return {
    generated_at: stamp,
    content: parseFfufJson(ffufJson ?? ""),
    findings,
    by_severity: countBySeverity(findings),
  }
}
