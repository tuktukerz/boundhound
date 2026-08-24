// Guard — best-effort defense-in-depth filter for the PreToolUse hook.
// It classifies a bash command string and denies attempts to run network
// tools directly (bypassing the bh-exec choke point). A static string
// classifier can NEVER be hermetic against a determined caller; the
// authoritative boundaries are (1) bh-exec's scope check and (2) the
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
// Wrapper commands that re-exec their remaining args as-is (sudo, timeout,
// env, ...). These must be peeled off before classifying the head token,
// otherwise `timeout 5 curl ...` / `sudo curl ...` / `env curl ...` etc.
// sail past the network-bin check disguised as an allowed wrapper.
const WRAPPERS = new Set(["sudo", "doas", "timeout", "env", "nice", "ionice", "nohup", "setsid", "xargs", "watch"])

function stripQuotes(t) {
  return t.replace(/^['"]+/, "").replace(/['"]+$/, "")
}

function isBhExec(token) {
  const t = stripQuotes(token)
  return t === "bh-exec" || /(^|\/)bh-exec(\.mjs)?$/.test(t)
}

// Strips leading grouping/negation characters left over from subshell or
// brace-group syntax, e.g. "(curl ...)" or "{ curl ...; }", so the head
// token underneath is still recognized.
function stripLeadingGroupers(s) {
  return s.replace(/^[({!]+\s*/, "")
}

export function classifyCommand(cmd) {
  const text = String(cmd).trim()
  // Split on shell separators, incl. newline and command-substitution openers.
  const parts = text.split(/(?:&&|\|\||;|\||\n|\r|\$\(|`)/).map((p) => p.trim()).filter(Boolean)
  for (const rawPart of parts) {
    const part = stripLeadingGroupers(rawPart)
    let tokens = part.split(/\s+/).filter(Boolean)
    // Skip leading KEY=VALUE env assignments.
    while (tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    if (!tokens.length) continue
    // Peel wrapper commands (sudo, timeout, env, nohup, xargs, ...), which
    // can chain (e.g. `sudo env FOO=bar timeout 5 curl ...`). Re-check for
    // the wrapper's own flags, timeout's duration argument, and further
    // env-var assignments after each peel.
    while (tokens.length) {
      const w = stripQuotes(tokens[0]).split("/").pop().toLowerCase()
      if (!WRAPPERS.has(w)) break
      tokens = tokens.slice(1)
      while (tokens.length && tokens[0].startsWith("-")) tokens = tokens.slice(1) // skip wrapper's own flags
      if (w === "timeout" && tokens.length && /^[\d.]+[smhd]?$/.test(tokens[0])) tokens = tokens.slice(1) // timeout's duration arg
      while (tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1) // env-vars again (e.g. after `env`)
    }
    if (!tokens.length) continue
    const headRaw = tokens[0]
    if (isBhExec(headRaw)) continue // sanctioned path
    const base = stripQuotes(headRaw).split("/").pop().toLowerCase()
    if (base === "docker" && (tokens[1] === "exec" || tokens[1] === "run")) {
      return { decision: "DENY", reason: `docker ${tokens[1]} bypass (use bh-exec)` }
    }
    if (INTERPRETERS.includes(base) && tokens.slice(1).some((t) => t === "-c" || t === "-e" || t === "-ce")) {
      return { decision: "DENY", reason: `interpreter inline code '${base}' (use bh-exec)` }
    }
    if (NETWORK_BINS.includes(base)) {
      return { decision: "DENY", reason: `direct network tool '${base}' (use bh-exec)` }
    }
  }
  return { decision: "ALLOW", reason: "non-network-or-sanctioned" }
}
