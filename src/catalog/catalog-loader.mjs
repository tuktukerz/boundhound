import { readFileSync } from "node:fs"

export class CatalogError extends Error {}

const REQUIRED = ["tools_name", "description", "category", "command", "phase"]

function validateEntry(e) {
  for (const k of REQUIRED) {
    if (e[k] == null) throw new CatalogError(`tool missing '${k}': ${JSON.stringify(e).slice(0, 80)}`)
  }
  if (!e.command.base) throw new CatalogError(`tool '${e.tools_name}' missing command.base`)
  for (const f of e.command.flags ?? []) {
    if (f.takes_value === true && !f.value_pattern) {
      throw new CatalogError(
        `tool '${e.tools_name}' flag '${f.name}' has takes_value:true but no value_pattern (fail-closed)`,
      )
    }
    // Structural anchoring invariant: value_pattern is matched with
    // .test(), which matches substrings anywhere in the string — an
    // unanchored pattern (missing ^ and/or $) would let a value-flag
    // argument smuggle extra content (e.g. an alternate host) past the
    // check. Anchoring is enforced here as a load-time structural
    // guarantee, not left as a catalog-authoring convention.
    if (f.takes_value === true && f.value_pattern) {
      const p = f.value_pattern
      if (!(p.startsWith("^") && p.endsWith("$"))) {
        throw new CatalogError(
          `tool '${e.tools_name}' flag '${f.name}' has value_pattern '${p}' that is not fully anchored ` +
            `(must start with '^' and end with '$'; .test() matches substrings, so an unanchored pattern ` +
            `can let a value smuggle extra content past the check)`,
        )
      }
    }
  }
}

export function loadCatalog(path, rawOverride) {
  let raw
  try {
    raw = rawOverride ?? readFileSync(path, "utf8")
  } catch (e) {
    throw new CatalogError(`cannot read catalog: ${e.message}`)
  }
  let parsed
  try { parsed = JSON.parse(raw) } catch (e) { throw new CatalogError(`invalid JSON: ${e.message}`) }
  if (!Array.isArray(parsed.tools)) throw new CatalogError("catalog.tools must be an array")
  for (const e of parsed.tools) validateEntry(e)
  return parsed
}

export function findTool(catalog, name) {
  return catalog.tools.find((t) => t.tools_name === name) ?? null
}
