// src/recon/recon-map.mjs
//
// Pure parsers + synthesizer for Phase 1 recon output. No I/O here on
// purpose (spec §2.4) — the CLI (bin/bh-recon-map.mjs) owns reading the raw
// tool output files and writing recon-map.json; these functions only ever
// see text in, structured data out, so they unit-test against fixtures with
// no filesystem involved.

// One JSON object per line (subfinder -json -silent output). Blank lines and
// lines that fail JSON.parse (or don't carry a string .host) are skipped
// rather than thrown on — recon tool output is not a contract we control.
export function parseSubfinderJsonl(text) {
  const hosts = []
  for (const rawLine of (text ?? "").split("\n")) {
    const line = rawLine.trim()
    if (!line) continue
    let obj
    try {
      obj = JSON.parse(line)
    } catch {
      continue
    }
    if (obj && typeof obj.host === "string") hosts.push(obj.host)
  }
  return hosts
}

// One JSON object per line (httpx -json -silent output). Same
// skip-on-blank/invalid rule as above. title/tech are treated as optional
// (httpx omits title for non-HTML responses, and tech is empty without -td)
// and default to null / [] respectively so every returned entry has the
// same shape.
export function parseHttpxJsonl(text) {
  const services = []
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
    services.push({
      url: obj.url ?? null,
      host: obj.host ?? null,
      status_code: obj.status_code ?? null,
      title: obj.title ?? null,
      tech: obj.tech ?? [],
    })
  }
  return services
}

// Each open port is rendered by nmap -oG as
// "<port>/<state>/<proto>/<owner>/<service>/<rpc info>/<version info>/" —
// only port/state/proto/service are kept, per spec §2.4's returned shape.
function parsePortToken(token) {
  const parts = token.trim().split("/")
  return {
    port: Number(parts[0]),
    proto: parts[2] ?? "",
    state: parts[1] ?? "",
    service: parts[4] ?? "",
  }
}

// Regex-based parser for nmap -oG ("grepable") output — deliberately NOT an
// XML parser (that's the whole reason the skill runs -oG, not -oX: no extra
// dependency). Only "Host:" lines that carry a "Ports:" segment become an
// entry; comment lines ("# Nmap ... scan initiated/done ...") and
// discovery-only "Host: ... Status: Up" lines (no port data) are skipped.
// A line that starts with "Host:" but doesn't match the expected shape is
// skipped rather than thrown on, same tolerance policy as the JSONL parsers.
export function parseNmapGrepable(text) {
  const hosts = []
  for (const rawLine of (text ?? "").split("\n")) {
    const line = rawLine.trim()
    if (!line || line.startsWith("#")) continue
    const hostMatch = line.match(/^Host:\s+(\S+)\s+\([^)]*\)/)
    if (!hostMatch) continue
    const portsMatch = line.match(/Ports:\s*([^\t]*)/)
    if (!portsMatch) continue
    const portsStr = portsMatch[1].trim()
    const ports = portsStr.length === 0
      ? []
      : portsStr.split(",").map((tok) => tok.trim()).filter(Boolean).map(parsePortToken)
    hosts.push({ host: hostMatch[1], ports })
  }
  return hosts
}

// Merges the three raw tool outputs into one normalized recon-map object.
// generated_at comes from an injected `now` (defaulted here, not at the call
// site) so callers get a real timestamp in production while tests stay
// deterministic by injecting their own.
export function buildReconMap({ subfinderJsonl, httpxJsonl, nmapGrepable } = {}, { now } = {}) {
  const stamp = (now ?? (() => new Date().toISOString()))()
  return {
    generated_at: stamp,
    subdomains: parseSubfinderJsonl(subfinderJsonl ?? ""),
    http_services: parseHttpxJsonl(httpxJsonl ?? ""),
    hosts: parseNmapGrepable(nmapGrepable ?? ""),
  }
}
