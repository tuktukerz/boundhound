// src/scope/active-engagement.mjs
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parseScope } from "./scope-parser.mjs"

export class NoActiveEngagement extends Error {}

export function activeName(rootDir) {
  try {
    const n = readFileSync(join(rootDir, "engagements", ".active"), "utf8").trim()
    return n || null
  } catch {
    return null
  }
}

export function loadActiveConfig(rootDir) {
  const name = activeName(rootDir)
  if (!name) throw new NoActiveEngagement("no active engagement")
  const path = join(rootDir, "engagements", name, "scope.yaml")
  const text = readFileSync(path, "utf8") // throws if missing -> fail-closed
  return parseScope(text)
}
