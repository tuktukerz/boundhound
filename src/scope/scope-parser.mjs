// src/scope/scope-parser.mjs
import { parse as parseYaml } from "yaml"

export class ScopeError extends Error {}

const ENFORCEMENT = new Set(["strict", "moderate", "none"])

function normList(x) {
  if (x == null) return []
  if (!Array.isArray(x)) throw new ScopeError("expected a list")
  return x.map(String)
}

function lowercaseDomains(domains) {
  return domains.map(d => d.toLowerCase())
}

function assertWildcardsSafe(domains) {
  for (const d of domains) {
    if (d === "*" || /^\*\.[^.]+$/.test(d)) {
      throw new ScopeError(`wildcard too broad (TLD-level): ${d}`)
    }
  }
}

function assertCidrValid(cidrs) {
  for (const c of cidrs) {
    const [net, bitsStr] = c.split("/")
    if (!bitsStr) throw new ScopeError(`invalid CIDR: ${c} (missing prefix length)`)
    const bits = Number(bitsStr)
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
      throw new ScopeError(`invalid CIDR: ${c} (prefix must be 0-32)`)
    }
    const octets = net.split(".")
    if (octets.length !== 4) throw new ScopeError(`invalid CIDR: ${c} (expected 4 octets)`)
    for (const octet of octets) {
      const val = Number(octet)
      if (!Number.isInteger(val) || val < 0 || val > 255) {
        throw new ScopeError(`invalid CIDR: ${c} (octets must be 0-255)`)
      }
    }
  }
}

export function parseScope(yamlString) {
  let raw
  try {
    raw = parseYaml(yamlString)
  } catch (e) {
    throw new ScopeError(`invalid YAML: ${e.message}`)
  }
  if (!raw || typeof raw !== "object") throw new ScopeError("empty scope")
  if (!raw.engagement) throw new ScopeError("missing engagement")
  if (!raw.authorization) throw new ScopeError("missing authorization")
  if (!ENFORCEMENT.has(raw.scope_enforcement)) {
    throw new ScopeError(`invalid scope_enforcement: ${raw.scope_enforcement}`)
  }
  const inDomains = lowercaseDomains(normList(raw.in_scope?.domains))
  const inCidrs = normList(raw.in_scope?.cidrs)
  const outDomains = lowercaseDomains(normList(raw.out_of_scope?.domains))
  const outCidrs = normList(raw.out_of_scope?.cidrs)

  assertWildcardsSafe(inDomains)
  assertCidrValid(inCidrs)
  assertCidrValid(outCidrs)

  const inScope = {
    domains: inDomains,
    cidrs: inCidrs,
  }
  const outScope = {
    domains: outDomains,
    cidrs: outCidrs,
  }
  return {
    engagement: String(raw.engagement),
    authorization: String(raw.authorization),
    mode: raw.mode ?? "auto",
    scope_enforcement: raw.scope_enforcement,
    in_scope: inScope,
    out_of_scope: outScope,
    safety_constraints: {
      block_destructive: raw.safety_constraints?.block_destructive ?? true,
      block_dos: raw.safety_constraints?.block_dos ?? true,
    },
    rate_limit: raw.rate_limit ?? null,
    notes: raw.notes ?? "",
  }
}
