import { test, expect } from "bun:test"
import { join } from "node:path"
import { loadCatalog, findTool, CatalogError } from "./catalog-loader.mjs"

const catalogPath = join(import.meta.dir, "..", "..", "tools-catalog.json")

test("loads the repo catalog", () => {
  const c = loadCatalog(catalogPath)
  expect(Array.isArray(c.tools)).toBe(true)
})

test("catalog contains the curl test tool", () => {
  const c = loadCatalog(catalogPath)
  const curl = findTool(c, "curl")
  expect(curl).not.toBeNull()
  expect(curl.command.base).toBe("curl")
  expect(curl.category).toBe("utility")
})

test("rejects a tool entry missing required fields", () => {
  const bad = JSON.stringify({ version: "1", tools: [{ tools_name: "x" }] })
  expect(() => loadCatalog(null, bad)).toThrow(CatalogError)
})
