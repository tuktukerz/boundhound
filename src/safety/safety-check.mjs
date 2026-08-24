// src/safety/safety-check.mjs

// Phase 0: minimal, generic rules. Enriched per-phase as new tools are added (spec §6).
const DESTRUCTIVE = [
  /--dump-all/i, /--os-shell/i, /--os-pwn/i, /\brm\s+-rf\b/i, /--flush-session/i,
  // Phase 3 (exploit, spec §2.2): sqlmap weaponizing flags. THE safety
  // centerpiece for the exploit phase — these turn a proof-of-vuln SQLi
  // confirmation into data exfiltration, RCE, file/registry access,
  // privilege escalation, or arbitrary code execution, and must be hard-
  // denied regardless of what the catalog allowlist declares.
  // Each is anchored on (start-of-string | whitespace) before the flag and
  // a word boundary after it, so it matches the flag itself and its
  // "=value" form, but never a benign flag that merely shares a prefix
  // (e.g. --dump must not match --dbms/--dbs; --dump-all keeps matching
  // via the trailing \b, since "-" is a non-word char).
  /(^|\s)--dump\b/i,        // table/DB contents dump (data exfiltration)
  /(^|\s)--os-cmd\b/i,      // single OS command execution
  /(^|\s)--sql-shell\b/i,   // interactive SQL shell
  /(^|\s)--sql-query\b/i,   // arbitrary SQL query execution
  /(^|\s)--file-read\b/i,   // read arbitrary file from DB server
  /(^|\s)--file-write\b/i,  // write arbitrary file to DB server
  /(^|\s)--file-dest\b/i,   // destination path for --file-write
  /(^|\s)--reg-read\b/i,    // Windows registry read
  /(^|\s)--reg-add\b/i,     // Windows registry write
  /(^|\s)--reg-del\b/i,     // Windows registry delete
  /(^|\s)--priv-esc\b/i,    // privilege escalation
  /(^|\s)--msf-path\b/i,    // Metasploit integration (payload delivery)
  /(^|\s)--os-smbrelay\b/i, // SMB relay attack / one-click shell
  /(^|\s)--eval\b/i,        // arbitrary Python code evaluation
  /(^|\s)--os-bof\b/i,      // buffer overflow exploitation
]
// Literal token denies: no numeric cap, the token itself is the violation.
// Case-sensitive by design: nmap timing templates are always uppercase (-T0..-T5).
// Lowercase -t/-t5 is the unrelated threads flag, governed only by the DOS numeric cap below.
const DOS_LITERAL = [
  { pattern: /^-T5$/, label: "-T5" }, // nmap insane timing template
]
const DOS = [
  { flag: "-t", max: 500 },          // threads (ffuf/gobuster style)
  { flag: "--threads", max: 500 },
  { flag: "--rate", max: 10000 },
  { flag: "-rate", max: 1000 },      // ffuf's real rate flag is single-dash; --rate above is a distinct (looser) cap some tools use
  { flag: "--min-rate", max: 5000 }, // nmap min packet rate
  { flag: "--max-rate", max: 5000 }, // nmap max packet rate
  { flag: "-c", max: 50 },           // nuclei template concurrency
  { flag: "-concurrency", max: 50 },
  { flag: "-rl", max: 1000 },        // nuclei requests/sec
  { flag: "-rate-limit", max: 1000 },
  // Phase 3 (exploit, spec §2.2): sqlmap aggressive-payload caps. --risk 3
  // issues heavy/OR-based queries that can modify data; --level above 3
  // adds increasingly invasive test payloads. sqlmap's --threads is
  // already covered by the existing "--threads" rule above (max 500).
  { flag: "--level", max: 3 },
  { flag: "--risk", max: 2 },
]

export function checkSafety(tool, args, constraints) {
  // Treat null/undefined constraints as strict (deny-by-default safe default)
  const blockDestructive = constraints?.block_destructive ?? true
  const blockDos = constraints?.block_dos ?? true

  const joined = args.join(" ")
  if (blockDestructive) {
    for (const re of DESTRUCTIVE) {
      if (re.test(joined)) return { decision: "DENY", reason: `destructive:${re}` }
    }
  }
  if (blockDos) {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]

      // Literal token denies (e.g., nmap -T5 insane timing), case-sensitive
      for (const lit of DOS_LITERAL) {
        if (lit.pattern.test(arg)) {
          return { decision: "DENY", reason: `dos:${lit.label}` }
        }
      }

      // Check for exact flag match (e.g., "-t 5000" or "--min-rate 100000"), case-insensitive
      const rule = DOS.find((d) => d.flag.toLowerCase() === arg.toLowerCase())
      if (rule) {
        const val = Number(args[i + 1])
        if (Number.isFinite(val) && val > rule.max) {
          return { decision: "DENY", reason: `dos:${rule.flag}=${val}>${rule.max}` }
        }
      }

      // Check for flag=value form (e.g., "--threads=5000" or "--min-rate=100000"), case-insensitive
      const lowerArg = arg.toLowerCase()
      for (const rule of DOS) {
        if (lowerArg.startsWith(rule.flag.toLowerCase() + "=")) {
          const valStr = arg.slice(rule.flag.length + 1)
          const val = Number(valStr)
          if (Number.isFinite(val) && val > rule.max) {
            return { decision: "DENY", reason: `dos:${rule.flag}=${val}>${rule.max}` }
          }
        }
      }

      // Check for glued short form (e.g., "-t5000")
      if (arg.startsWith("-t") && arg.length > 2 && !arg.startsWith("--")) {
        const valStr = arg.slice(2)
        const val = Number(valStr)
        if (Number.isFinite(val) && val > 500) {  // -t max is 500
          return { decision: "DENY", reason: `dos:-t=${val}>500` }
        }
      }
    }
  }
  return { decision: "ALLOW", reason: "safety-ok" }
}
