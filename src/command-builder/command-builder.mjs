export function buildCommand(entry, { target, extraArgs = [] } = {}) {
  const needsTarget = (entry.command.positional ?? []).some((p) => p.required)
  if (needsTarget && !target) throw new Error("required positional target missing")
  const argv = [entry.command.base, ...extraArgs]
  if (target) argv.push(target)
  return argv
}
