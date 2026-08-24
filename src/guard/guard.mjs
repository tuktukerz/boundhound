const NETWORK_BINS = [
  "curl", "wget", "nc", "ncat", "netcat", "nmap", "masscan", "naabu",
  "ping", "telnet", "ssh", "ftp", "nuclei", "httpx", "ffuf", "gobuster",
  "sqlmap", "nikto", "subfinder", "amass", "katana", "dalfox",
]

function isOmopExec(token) {
  return token === "omop-exec" || /(^|\/)omop-exec(\.mjs)?$/.test(token)
}

export function classifyCommand(cmd) {
  const text = String(cmd).trim()
  // Split into sub-commands on shell separators to catch chained bypass.
  const parts = text.split(/(?:&&|\|\||;|\|)/).map((p) => p.trim()).filter(Boolean)
  for (const part of parts) {
    const tokens = part.split(/\s+/)
    const head = tokens[0] ?? ""
    if (isOmopExec(head)) continue // sanctioned path
    // docker exec bypass
    if (head === "docker" && tokens[1] === "exec") {
      return { decision: "DENY", reason: "docker-exec bypass (use omop-exec)" }
    }
    // direct network binary anywhere as a command head
    const base = head.split("/").pop()
    if (NETWORK_BINS.includes(base)) {
      return { decision: "DENY", reason: `direct network tool '${base}' (use omop-exec)` }
    }
  }
  return { decision: "ALLOW", reason: "non-network-or-sanctioned" }
}
