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

function toolWithFlags(flags) {
  return JSON.stringify({
    version: "1",
    tools: [
      {
        tools_name: "x",
        description: "d",
        category: "recon",
        phase: 1,
        command: { base: "x", flags },
      },
    ],
  })
}

test("rejects a takes_value:true flag with no value_pattern (fail-closed)", () => {
  const bad = toolWithFlags([{ name: "-p", takes_value: true }])
  expect(() => loadCatalog(null, bad)).toThrow(CatalogError)
})

test("loads a takes_value:true flag that has a value_pattern", () => {
  const ok = toolWithFlags([{ name: "-p", takes_value: true, value_pattern: "^[0-9]+$" }])
  const c = loadCatalog(null, ok)
  expect(findTool(c, "x").command.flags[0].name).toBe("-p")
})

test("loads a boolean flag with no takes_value", () => {
  const ok = toolWithFlags([{ name: "-sV", description: "service detection" }])
  const c = loadCatalog(null, ok)
  expect(findTool(c, "x").command.flags[0].name).toBe("-sV")
})
