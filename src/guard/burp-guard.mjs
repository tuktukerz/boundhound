// src/guard/burp-guard.mjs
//
// Decision core of the SECOND choke point (Phase 8 spec §2). Burp Suite runs
// on the host and issues its own HTTP requests, so Burp MCP tool calls never
// pass through bh-exec's scope check. This module is called from the
// PreToolUse hook (Task 2) before any mcp__*burp*__* tool call is allowed to
// run.
//
// This is a SECURITY module: deny-by-default and fail-closed are the whole
// point. Every function here is pure (no I/O, no Date.now()/Math.random())
// and NEVER throws -- an unexpected shape of input must resolve to a DENY,
// never an exception that a caller might mishandle as an implicit allow, and
// never a false ALLOW. A false-deny (blocking a legitimate call) is an
// acceptable, recoverable annoyance; a false-allow is a Critical defect.
//
// A security review of the first cut found a fail-open gap: reading only the
// FIRST present target field (url > target > targetUrl > host > raw request)
// means a caller can put the real (out-of-scope) destination in a field we
// don't look at (or a second Host: header) and a decoy in-scope value in the
// field we check first -- and the decoy wins. The fix (below) collects EVERY
// candidate target present anywhere in the arguments and DENIES on
// disagreement instead of trusting whichever one happened to be checked
// first. Disagreement is itself treated as suspicious: legitimate tool
// arguments describe one target, so if two fields describe two different
// hosts, something is wrong and we fail closed.
import { matchTarget, normalizeTarget } from "../scope/scope-matcher.mjs"

// True iff `toolName` names an MCP tool routed through a Burp MCP server --
// i.e. it starts with "mcp__" and contains "burp" (case-insensitive)
// somewhere in the server/tool segment (e.g. "mcp__burp__send_request",
// "mcp__pro_burp__scan"). Guards against non-string input rather than
// throwing on e.g. `.startsWith`, and wrapped so even a hostile
// String-subclass-like value with throwing methods can't escape as a throw.
export function isBurpMcpTool(toolName) {
  try {
    if (typeof toolName !== "string" || toolName.length === 0) return false
    if (!toolName.startsWith("mcp__")) return false
    return toolName.toLowerCase().includes("burp")
  } catch {
    return false
  }
}

// Pulls the request-line absolute URL ("METHOD http://host/path HTTP/1.1")
// out of a raw HTTP request string, if present.
function requestLineUrl(text) {
  const m = /^[A-Za-z]+\s+(https?:\/\/\S+)\s+HTTP\/[\d.]+/m.exec(text)
  return m ? m[1] : null
}

// Pulls the value of EVERY `Host:` header out of a raw HTTP request string.
// Header names are case-insensitive per RFC 7230; each value is trimmed of
// surrounding whitespace and any trailing \r. Collecting all of them (not
// just the first) matters: a request smuggling a second, disagreeing Host
// header is exactly the kind of thing that must be treated as suspicious
// rather than silently resolved by "first wins" or "last wins".
function allHostHeaders(text) {
  const hosts = []
  const re = /^Host:[ \t]*([^\r\n]+)/gim
  let m
  while ((m = re.exec(text)) !== null) {
    const v = m[1].trim()
    if (v.length > 0) hosts.push(v)
  }
  return hosts
}

// Extracts every target candidate embedded in a raw HTTP request string: the
// request-line's absolute URL (if present) plus every Host header value.
function targetsFromRawRequest(text) {
  if (typeof text !== "string" || text.length === 0) return []
  const out = []
  const lineUrl = requestLineUrl(text)
  if (lineUrl) out.push(lineUrl)
  out.push(...allHostHeaders(text))
  return out
}

// Collects EVERY target candidate string present in Burp MCP tool arguments
// (spec §2 + security-review fix), purely via structural string inspection --
// no network access, no parsing libraries that could throw on malformed
// input. Order (also `extractBurpTarget`'s precedence, see below): url,
// target, targetUrl, host(+port), then each raw request field
// (request/httpRequest/rawRequest) contributing its request-line URL and
// every Host header it carries. Returns [] when `toolInput` isn't a usable
// object or nothing usable is found.
//
// This is deliberately exhaustive rather than "first match wins": a caller
// (or the tool's own JSON) can carry several of these fields at once, and
// `decideBurpMcp` needs to see all of them to detect disagreement between
// fields (e.g. an in-scope decoy `url` alongside an out-of-scope `host`).
// Wrapped so a hostile object with a throwing getter on any property can
// never escape this function as a throw -- worst case it degrades to
// whatever candidates were already collected, or [].
export function extractBurpTargets(toolInput) {
  try {
    const out = []
    if (!toolInput || typeof toolInput !== "object" || Array.isArray(toolInput)) return out

    if (typeof toolInput.url === "string" && toolInput.url.length > 0) out.push(toolInput.url)
    if (typeof toolInput.target === "string" && toolInput.target.length > 0) out.push(toolInput.target)
    if (typeof toolInput.targetUrl === "string" && toolInput.targetUrl.length > 0) out.push(toolInput.targetUrl)

    if (typeof toolInput.host === "string" && toolInput.host.length > 0) {
      const port = toolInput.port
      if (typeof port === "string" || typeof port === "number") {
        const portStr = String(port).trim()
        out.push(portStr.length > 0 ? `${toolInput.host}:${portStr}` : toolInput.host)
      } else {
        out.push(toolInput.host)
      }
    }

    for (const field of ["request", "httpRequest", "rawRequest"]) {
      out.push(...targetsFromRawRequest(toolInput[field]))
    }

    return out
  } catch {
    return []
  }
}

// Single-target convenience wrapper kept for callers that only want "the"
// target (e.g. audit-detail logging in Task 2): the first candidate in
// `extractBurpTargets`' priority order, or null when there are none. NEVER
// use this for the scope decision itself -- `decideBurpMcp` uses the full
// candidate set so it can catch disagreement between fields, which a
// single "first present" value can't see.
export function extractBurpTarget(toolInput) {
  const targets = extractBurpTargets(toolInput)
  return targets.length > 0 ? targets[0] : null
}

// Characters that make a candidate target string untrustworthy as an
// "authority" (host[:port]) regardless of what our own normalizeTarget
// makes of it: backslash, any whitespace, and ASCII control characters
// (including DEL). Rationale (parser-differential hardening): our JS
// WHATWG URL parser and Burp's own (Java) request/URL handling can disagree
// on how a string like "http://acme.io\@evil.com/" splits into
// scheme/authority/path -- WHATWG treats "\" as a path separator for
// special schemes and resolves the hostname to "acme.io", while a naive
// "split on the last @" parser would read "evil.com" as the host. Rather
// than trust either parser's opinion of a non-standard authority string, we
// refuse to resolve scope from it at all.
const SUSPICIOUS_CHARS = /[\\\s\x00-\x1F\x7F]/

function isSuspiciousCandidate(candidate) {
  return typeof candidate === "string" && SUSPICIOUS_CHARS.test(candidate)
}

// Deny-by-default, fail-closed decision for a Burp MCP tool call (spec §2 +
// security-review fix):
// - No active/valid scope config -> DENY "no-active-scope" (nothing to
//   check against, so nothing is allowed).
// - No target candidate found anywhere in the arguments -> DENY
//   "burp-target-unresolved" (can't verify scope, so it can't be trusted).
// - Any candidate contains a backslash/whitespace/control character -> DENY
//   "burp-target-suspicious" (parser-differential hardening -- see
//   SUSPICIOUS_CHARS above; never let a non-standard-authority string
//   resolve to an in-scope host).
// - The candidates normalize to more than one DISTINCT host -> DENY
//   "burp-target-ambiguous" (disagreement between fields is itself
//   suspicious -- a decoy in-scope field alongside a real out-of-scope one
//   must not resolve to ALLOW just because the decoy was checked first;
//   agreeing duplicates, e.g. the same host repeated in `url` and `host`,
//   are NOT ambiguous).
// - Exactly one distinct host -> defer verbatim to the same scope matcher
//   bh-exec uses (`matchTarget`), so Burp calls are held to the exact same
//   in/out-of-scope rules as every other tool.
// Wrapped so that literally any unexpected error (a malformed scopeConfig
// that makes matchTarget throw, etc.) resolves to a DENY -- never a throw,
// never a false ALLOW.
export function decideBurpMcp(toolInput, scopeConfig) {
  try {
    if (!scopeConfig) return { decision: "DENY", reason: "no-active-scope" }

    const candidates = extractBurpTargets(toolInput)
    if (candidates.length === 0) return { decision: "DENY", reason: "burp-target-unresolved" }

    if (candidates.some(isSuspiciousCandidate)) {
      return { decision: "DENY", reason: "burp-target-suspicious" }
    }

    const distinctHosts = new Set(candidates.map((c) => normalizeTarget(c)))
    if (distinctHosts.size > 1) {
      return { decision: "DENY", reason: "burp-target-ambiguous" }
    }

    return matchTarget(candidates[0], scopeConfig)
  } catch {
    return { decision: "DENY", reason: "burp-guard-error" }
  }
}
