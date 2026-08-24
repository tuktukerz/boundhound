// src/safety/safety-check.mjs

// Fase 0: aturan minimal & generik. Diperkaya per-fase saat tool masuk (spec §6).
const DESTRUCTIVE = [/--dump-all/, /--os-shell/, /--os-pwn/, /\brm\s+-rf\b/, /--flush-session/]
const DOS = [
  { flag: "-t", max: 500 },        // threads (ffuf/gobuster style)
  { flag: "--threads", max: 500 },
  { flag: "--rate", max: 10000 },
]

export function checkSafety(tool, args, constraints) {
  const joined = args.join(" ")
  if (constraints?.block_destructive) {
    for (const re of DESTRUCTIVE) {
      if (re.test(joined)) return { decision: "DENY", reason: `destructive:${re}` }
    }
  }
  if (constraints?.block_dos) {
    for (let i = 0; i < args.length; i++) {
      const rule = DOS.find((d) => d.flag === args[i])
      if (rule) {
        const val = Number(args[i + 1])
        if (Number.isFinite(val) && val > rule.max) {
          return { decision: "DENY", reason: `dos:${rule.flag}=${val}>${rule.max}` }
        }
      }
    }
  }
  return { decision: "ALLOW", reason: "safety-ok" }
}
