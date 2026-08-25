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
import { matchTarget } from "../scope/scope-matcher.mjs"

// True iff `toolName` names an MCP tool routed through a Burp MCP server --
// i.e. it starts with "mcp__" and contains "burp" (case-insensitive)
// somewhere in the server/tool segment (e.g. "mcp__burp__send_request",
// "mcp__pro_burp__scan"). Guards against non-string input rather than
// throwing on e.g. `.startsWith`.
export function isBurpMcpTool(toolName) {
  if (typeof toolName !== "string" || toolName.length === 0) return false
  if (!toolName.startsWith("mcp__")) return false
  return toolName.toLowerCase().includes("burp")
}

// Pulls the request-line absolute URL ("METHOD http://host/path HTTP/1.1")
// out of a raw HTTP request string, if present.
function requestLineUrl(text) {
  const m = /^[A-Za-z]+\s+(https?:\/\/\S+)\s+HTTP\/[\d.]+/m.exec(text)
  return m ? m[1] : null
}

// Pulls the value of a `Host:` header out of a raw HTTP request string, if
// present. Header names are case-insensitive per RFC 7230; the value is
// trimmed of surrounding whitespace and any trailing \r.
function requestHostHeader(text) {
  const m = /^Host:[ \t]*([^\r\n]+)/im.exec(text)
  return m ? m[1].trim() : null
}

// Extracts a target host/URL from a raw HTTP request string: prefer the
// request-line's absolute URL (it carries scheme+host+path), fall back to
// the Host header (host[:port] only).
function targetFromRawRequest(text) {
  if (typeof text !== "string" || text.length === 0) return null
  return requestLineUrl(text) ?? requestHostHeader(text) ?? null
}

// Extracts a target host/URL from Burp MCP tool arguments (spec §2), purely
// via structural string inspection -- no network access, no parsing
// libraries that could throw on malformed input. Checks fields in priority
// order: url, target, targetUrl, host(+port), then raw request fields
// (request/httpRequest/rawRequest) for a request-line URL or Host header.
// Returns null when nothing usable is found -- including when `toolInput`
// itself isn't a usable object.
export function extractBurpTarget(toolInput) {
  if (!toolInput || typeof toolInput !== "object" || Array.isArray(toolInput)) return null

  if (typeof toolInput.url === "string" && toolInput.url.length > 0) return toolInput.url
  if (typeof toolInput.target === "string" && toolInput.target.length > 0) return toolInput.target
  if (typeof toolInput.targetUrl === "string" && toolInput.targetUrl.length > 0) return toolInput.targetUrl

  if (typeof toolInput.host === "string" && toolInput.host.length > 0) {
    const port = toolInput.port
    if (typeof port === "string" || typeof port === "number") {
      const portStr = String(port).trim()
      if (portStr.length > 0) return `${toolInput.host}:${portStr}`
    }
    return toolInput.host
  }

  for (const field of ["request", "httpRequest", "rawRequest"]) {
    const found = targetFromRawRequest(toolInput[field])
    if (found) return found
  }

  return null
}

// Deny-by-default, fail-closed decision for a Burp MCP tool call (spec §2).
// - No active/valid scope config -> DENY "no-active-scope" (nothing to
//   check against, so nothing is allowed).
// - Target can't be resolved from the tool arguments -> DENY
//   "burp-target-unresolved" (can't verify scope, so it can't be trusted).
// - Otherwise, defer verbatim to the same scope matcher bh-exec uses
//   (`matchTarget`), so Burp calls are held to the exact same in/out-of-scope
//   rules as every other tool.
// Wrapped so that literally any unexpected error (a malformed scopeConfig
// that makes matchTarget throw, etc.) resolves to a DENY -- never a throw,
// never a false ALLOW.
export function decideBurpMcp(toolInput, scopeConfig) {
  try {
    if (!scopeConfig) return { decision: "DENY", reason: "no-active-scope" }

    const target = extractBurpTarget(toolInput)
    if (target === null) return { decision: "DENY", reason: "burp-target-unresolved" }

    return matchTarget(target, scopeConfig)
  } catch {
    return { decision: "DENY", reason: "burp-guard-error" }
  }
}
