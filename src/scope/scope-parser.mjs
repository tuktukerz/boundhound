// src/scope/scope-parser.mjs
import { parse as parseYaml } from "yaml"

export class ScopeError extends Error {}

const ENFORCEMENT = new Set(["strict", "moderate", "none"])

function normList(x) {
  if (x == null) return []
  if (!Array.isArray(x)) throw new ScopeError("expected a list")
  return x.map(String)
}

function assertWildcardsSafe(domains) {
  for (const d of domains) {
    if (d === "*" || /^\*\.[^.]+$/.test(d)) {
      throw new ScopeError(`wildcard too broad (TLD-level): ${d}`)
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
  const inScope = {
    domains: normList(raw.in_scope?.domains),
    cidrs: normList(raw.in_scope?.cidrs),
  }
  const outScope = {
    domains: normList(raw.out_of_scope?.domains),
    cidrs: normList(raw.out_of_scope?.cidrs),
  }
  assertWildcardsSafe(inScope.domains)
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
