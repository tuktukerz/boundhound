// src/scope/scope-matcher.mjs

export function normalizeTarget(raw) {
  let s = String(raw).trim()
  if (s.includes("://")) {
    try { s = new URL(s).hostname } catch { /* fall through */ }
  } else {
    s = s.split("/")[0]        // strip path
    s = s.split(":")[0]        // strip port
  }
  return s.toLowerCase()
}

function isIPv4(s) {
  const octets = s.split(".")
  if (octets.length !== 4) return false
  for (const octet of octets) {
    const val = Number(octet)
    if (!Number.isInteger(val) || val < 0 || val > 255) return false
  }
  return true
}

function ipToInt(ip) {
  return ip.split(".").reduce((acc, o) => (acc << 8) + (Number(o) & 255), 0) >>> 0
}

function inCidr(ip, cidr) {
  if (!isIPv4(ip)) return false
  const [net, bitsStr] = cidr.split("/")
  const bits = Number(bitsStr)
  if (!isIPv4(net) || !(bits >= 0 && bits <= 32)) return false
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (ipToInt(ip) & mask) === (ipToInt(net) & mask)
}

function domainMatches(host, rule) {
  rule = rule.toLowerCase()
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(1)        // ".acme.com"
    return host.endsWith(suffix) && host.length > suffix.length
  }
  return host === rule
}

function matchesAny(host, { domains, cidrs }) {
  for (const d of domains) if (domainMatches(host, d)) return d
  if (isIPv4(host)) for (const c of cidrs) if (inCidr(host, c)) return c
  return null
}

export function matchTarget(target, config) {
  const host = normalizeTarget(target)
  const out = matchesAny(host, config.out_of_scope ?? { domains: [], cidrs: [] })
  if (out) return { decision: "DENY", reason: `out_of_scope:${out}` }
  const inn = matchesAny(host, config.in_scope ?? { domains: [], cidrs: [] })
  if (inn) return { decision: "ALLOW", reason: `in_scope:${inn}` }
  return { decision: "DENY", reason: "deny-by-default" }
}
