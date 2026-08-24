export function buildCommand(entry, { target, extraArgs = [] } = {}) {
  const targetFlag = entry.command.target_flag ?? null
  const needsTarget = targetFlag != null || (entry.command.positional ?? []).some((p) => p.required)
  if (needsTarget && !target) throw new Error("required target missing")
  const argv = [entry.command.base, ...extraArgs]
  if (target) {
    if (targetFlag) argv.push(targetFlag, target) // e.g. subfinder -d acme.io
    else argv.push(target) // e.g. nmap 1.2.3.4 (unchanged path)
  }
  return argv
}
