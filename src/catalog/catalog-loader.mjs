import { readFileSync } from "node:fs"

export class CatalogError extends Error {}

const REQUIRED = ["tools_name", "description", "category", "command", "phase"]

function validateEntry(e) {
  for (const k of REQUIRED) {
    if (e[k] == null) throw new CatalogError(`tool missing '${k}': ${JSON.stringify(e).slice(0, 80)}`)
  }
  if (!e.command.base) throw new CatalogError(`tool '${e.tools_name}' missing command.base`)
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
