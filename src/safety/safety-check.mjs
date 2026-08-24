// src/safety/safety-check.mjs

// Fase 0: aturan minimal & generik. Diperkaya per-fase saat tool masuk (spec §6).
const DESTRUCTIVE = [/--dump-all/i, /--os-shell/i, /--os-pwn/i, /\brm\s+-rf\b/i, /--flush-session/i]
const DOS = [
  { flag: "-t", max: 500 },        // threads (ffuf/gobuster style)
  { flag: "--threads", max: 500 },
  { flag: "--rate", max: 10000 },
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

      // Check for exact flag match (e.g., "-t 5000" or "--threads 5000")
      const rule = DOS.find((d) => d.flag === arg)
      if (rule) {
        const val = Number(args[i + 1])
        if (Number.isFinite(val) && val > rule.max) {
          return { decision: "DENY", reason: `dos:${rule.flag}=${val}>${rule.max}` }
        }
      }

      // Check for flag=value form (e.g., "--threads=5000" or "--rate=50000")
      for (const rule of DOS) {
        if (arg.startsWith(rule.flag + "=")) {
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
