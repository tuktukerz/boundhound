// Guard — best-effort defense-in-depth filter for the PreToolUse hook.
// It classifies a bash command string and denies attempts to run network
// tools directly (bypassing the omop-exec choke point). A static string
// classifier can NEVER be hermetic against a determined caller; the
// authoritative boundaries are (1) omop-exec's scope check and (2) the
// container sandbox. Hermetic network egress-lock is deferred (see spec
// docs/specs Fase 6/7 hardening). This filter closes the cheap, common
// bypasses and raises the bar.

const NETWORK_BINS = [
  "curl", "wget", "nc", "ncat", "netcat", "nmap", "masscan", "naabu", "ping",
  "telnet", "ssh", "scp", "sftp", "ftp", "rsync", "dig", "nslookup", "host",
  "openssl", "aria2c", "axel", "nuclei", "httpx", "ffuf", "gobuster", "sqlmap",
  "nikto", "subfinder", "amass", "katana", "dalfox",
]
const INTERPRETERS = ["bash", "sh", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node"]

function stripQuotes(t) {
  return t.replace(/^['"]+/, "").replace(/['"]+$/, "")
}

function isOmopExec(token) {
  const t = stripQuotes(token)
  return t === "omop-exec" || /(^|\/)omop-exec(\.mjs)?$/.test(t)
}

export function classifyCommand(cmd) {
  const text = String(cmd).trim()
  // Split on shell separators, incl. newline and command-substitution openers.
  const parts = text.split(/(?:&&|\|\||;|\||\n|\r|\$\(|`)/).map((p) => p.trim()).filter(Boolean)
  for (const part of parts) {
    let tokens = part.split(/\s+/).filter(Boolean)
    // Skip leading KEY=VALUE env assignments.
    while (tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    if (!tokens.length) continue
    const headRaw = tokens[0]
    if (isOmopExec(headRaw)) continue // sanctioned path
    const base = stripQuotes(headRaw).split("/").pop().toLowerCase()
    if (base === "docker" && (tokens[1] === "exec" || tokens[1] === "run")) {
      return { decision: "DENY", reason: `docker ${tokens[1]} bypass (use omop-exec)` }
    }
    if (INTERPRETERS.includes(base) && tokens.slice(1).some((t) => t === "-c" || t === "-e" || t === "-ce")) {
      return { decision: "DENY", reason: `interpreter inline code '${base}' (use omop-exec)` }
    }
    if (NETWORK_BINS.includes(base)) {
      return { decision: "DENY", reason: `direct network tool '${base}' (use omop-exec)` }
    }
  }
  return { decision: "ALLOW", reason: "non-network-or-sanctioned" }
}
