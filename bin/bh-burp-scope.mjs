// bin/bh-burp-scope.mjs
//
// Thin CLI: mirrors the active engagement's scope.yaml into a Burp Suite
// Target Scope (Phase 8 spec §4) -- defense-in-depth "second fence". Burp
// runs on the host and its MCP tool calls never pass through bh-exec's
// scope check (src/guard/burp-guard.mjs's PreToolUse hook is the FIRST
// fence), so this CLI lets the operator ALSO load the same scope directly
// into Burp itself (Target -> Scope -> Load). Not a network tool -- it
// only reads scope.yaml (already produced by bh-engagement) and renders
// it, so it runs as plain `node bin/bh-burp-scope.mjs` (no docker exec
// involved).
//
// ---------------------------------------------------------------------------
// Mapping (documented here since this is the only place it's defined):
//
//   in_scope.domains      -> target.scope.include entries
//   in_scope.cidrs        -> target.scope.include entries
//   out_of_scope.domains  -> target.scope.exclude entries
//   out_of_scope.cidrs    -> target.scope.exclude entries
//
// Each entry is { enabled: true, host: <string>, protocol: "any" }, Burp's
// Target Scope import shape. `host` for a DOMAIN is a REGEX (Burp matches
// `host` as a regex against the request's Host header):
//   - a plain domain "acme.io"  -> "^acme\.io$"          (exact host only)
//   - a wildcard "*.acme.com"   -> "^(.*\.)?acme\.com$"  (matches acme.com
//                                   itself AND any subdomain of it)
// Regex metacharacters in the literal part of the domain (in practice just
// "." for a validated domain name, but the escaper doesn't assume that) are
// escaped so the regex matches a LITERAL character rather than "any
// character".
//
// A CIDR entry is host-oriented in Burp too (Burp's own scope editor
// accepts a literal IP address or IP range in the `host` field), NOT a
// regex, so a CIDR ("10.0.0.0/24") is carried through VERBATIM as the host
// string -- it is deliberately NOT passed through the regex escaper, since
// it is not a regex.
//
// Output is fully deterministic: no Date.now()/Math.random()/new Date()
// anywhere in this module, and every include/exclude list is built by
// mapping scope.yaml's own arrays in their on-disk order -- so the same
// scope.yaml always renders byte-identical JSON.
import { join } from "node:path"
import { writeFileSync, mkdirSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { activeName, loadActiveConfig } from "../src/scope/active-engagement.mjs"
import { dataRoot } from "../src/paths.mjs"

// Escapes every regex metacharacter in a literal string so it matches only
// itself once embedded in a RegExp (the standard "escape for embedding in
// a regex" character class).
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

// Domain -> Burp host-regex (see header comment for the exact mapping).
export function domainToHostRegex(domain) {
  if (domain.startsWith("*.")) {
    const suffix = domain.slice(2) // "*.acme.com" -> "acme.com"
    return `^(.*\\.)?${escapeRegex(suffix)}$`
  }
  return `^${escapeRegex(domain)}$`
}

function domainEntry(domain) {
  return { enabled: true, host: domainToHostRegex(domain), protocol: "any" }
}

// CIDR entries carry the CIDR through verbatim (see header comment) --
// deliberately NOT escaped, since it isn't a regex.
function cidrEntry(cidr) {
  return { enabled: true, host: cidr, protocol: "any" }
}

// Pure: scope.yaml's parsed shape (src/scope/scope-parser.mjs's parseScope
// output -- in_scope/out_of_scope each { domains, cidrs }) -> a Burp Target
// Scope import object.
export function buildBurpScope(scope) {
  const include = [
    ...scope.in_scope.domains.map(domainEntry),
    ...scope.in_scope.cidrs.map(cidrEntry),
  ]
  const exclude = [
    ...scope.out_of_scope.domains.map(domainEntry),
    ...scope.out_of_scope.cidrs.map(cidrEntry),
  ]
  return { target: { scope: { advanced_mode: true, include, exclude } } }
}

export function runBurpScope({ dataDir } = {}) {
  const dDir = dataDir ?? dataRoot()
  const name = activeName(dDir)
  if (!name) return { code: 3, message: "fail-closed: no active engagement" }

  // loadActiveConfig re-reads scope.yaml through parseScope, which throws on
  // a missing file or any rule violation (missing engagement/authorization,
  // invalid scope_enforcement, bad CIDR, TLD-level wildcard, ...). Mirroring
  // a broken engagement's scope into Burp is refused, consistent with the
  // rest of the system's deny-by-default posture (spec §3) -- fail-closed,
  // nothing written.
  let meta
  try {
    meta = loadActiveConfig(dDir)
  } catch (e) {
    return { code: 3, message: `fail-closed: broken scope (${e.message})` }
  }

  const burpScope = buildBurpScope(meta)
  const json = JSON.stringify(burpScope, null, 2) + "\n"

  // target-scope.json is written into output/burp/, mirroring bh-report's
  // output/report/ and bh-findings' output/verify/ convention. mkdir -p
  // defensively: an engagement that hasn't run this before won't have
  // output/burp/ on disk yet.
  const outDir = join(dDir, "engagements", name, "output", "burp")
  mkdirSync(outDir, { recursive: true })
  const outPath = join(outDir, "target-scope.json")
  writeFileSync(outPath, json)

  return { code: 0, message: `wrote ${outPath}`, path: outPath, scope: burpScope, json }
}

// Optional "--data-dir <path>" pair, same convention/rationale as
// bh-report.mjs / bh-exec.mjs / bh-engagement.mjs / bh-enum-map.mjs /
// bh-recon-map.mjs / bh-exploit-map.mjs / bh-findings.mjs: plugin-mode
// agent invocations pass the data dir explicitly since ${CLAUDE_PLUGIN_DATA}
// isn't exported to the agent's Bash tool session.
function extractDataDir(argv) {
  const i = argv.indexOf("--data-dir")
  if (i < 0) return { dataDir: null, rest: argv }
  const dataDir = argv[i + 1]
  return { dataDir, rest: [...argv.slice(0, i), ...argv.slice(i + 2)] }
}

// CLI entry: import.meta.main is a Bun/Deno-ism and undefined under Node, so
// it must not gate the entrypoint here -- same argv-identity idiom as
// bh-report.mjs / bh-exec.mjs / bh-engagement.mjs / bh-enum-map.mjs /
// bh-recon-map.mjs / bh-exploit-map.mjs / bh-findings.mjs.
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const { dataDir } = extractDataDir(process.argv.slice(2))
  const r = runBurpScope(dataDir ? { dataDir } : {})
  // Per spec §4: on success the Burp scope JSON itself goes to stdout (so
  // the operator can pipe/redirect it directly), while the short status
  // note goes to stderr -- same stdout/stderr split as every other bin's
  // "data vs. diagnostics" convention, just with data as the success
  // payload instead of silence. On failure, nothing is written and the
  // fail-closed reason goes to stderr only (stdout stays empty).
  if (r.code === 0) {
    process.stdout.write(r.json)
    process.stderr.write(r.message + "\n")
  } else if (r.message) {
    process.stderr.write(r.message + "\n")
  }
  process.exit(r.code)
}
