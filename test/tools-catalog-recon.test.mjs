// test/tools-catalog-recon.test.mjs
//
// Phase 1 recon (Task 4): tools-catalog.json gains subfinder/httpx/nmap
// entries alongside the existing curl entry. This is a static structural
// check on the catalog data itself (loads via the real loader, which
// fail-closed-rejects any takes_value flag lacking a value_pattern — Task 1),
// not a behavioral test of command-builder/bh-exec (those have their own
// suites).
import { test, expect } from "bun:test"
import { join } from "node:path"
import { loadCatalog, findTool } from "../src/catalog/catalog-loader.mjs"

const catalogPath = join(import.meta.dir, "..", "tools-catalog.json")

// Exact strings from spec §4 / task-4-brief — Task 2's tests use the same
// literals, so these must not drift.
const NMAP_PORT_PATTERN = "^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$"
const NMAP_OG_PATTERN = "^-$"

function flagByName(entry, name) {
  return entry.command.flags.find((f) => f.name === name)
}

test("catalog loads successfully with recon tools present", () => {
  expect(() => loadCatalog(catalogPath)).not.toThrow()
})

test("curl entry still loads (untouched)", () => {
  const c = loadCatalog(catalogPath)
  const curl = findTool(c, "curl")
  expect(curl).not.toBeNull()
  expect(curl.command.base).toBe("curl")
  expect(curl.category).toBe("utility")
})

test("catalog declares the recon category", () => {
  const c = loadCatalog(catalogPath)
  expect(c.categories).toContain("recon")
})

test("findTool returns subfinder, httpx, and nmap", () => {
  const c = loadCatalog(catalogPath)
  expect(findTool(c, "subfinder")).not.toBeNull()
  expect(findTool(c, "httpx")).not.toBeNull()
  expect(findTool(c, "nmap")).not.toBeNull()
})

test("subfinder targets via -d and has expected boolean flags", () => {
  const c = loadCatalog(catalogPath)
  const subfinder = findTool(c, "subfinder")
  expect(subfinder.command.base).toBe("subfinder")
  expect(subfinder.command.target_flag).toBe("-d")
  expect(subfinder.category).toBe("recon")
  expect(subfinder.phase).toEqual(["recon"])
  expect(subfinder.requires_root).toBe(false)
  const flagNames = subfinder.command.flags.map((f) => f.name).sort()
  expect(flagNames).toEqual(["-json", "-silent"])
  for (const f of subfinder.command.flags) {
    expect(f.takes_value).not.toBe(true)
  }
})

test("httpx targets via -u and has expected boolean flags", () => {
  const c = loadCatalog(catalogPath)
  const httpx = findTool(c, "httpx")
  expect(httpx.command.base).toBe("httpx")
  expect(httpx.command.target_flag).toBe("-u")
  expect(httpx.category).toBe("recon")
  expect(httpx.phase).toEqual(["recon"])
  expect(httpx.requires_root).toBe(false)
  const flagNames = httpx.command.flags.map((f) => f.name).sort()
  expect(flagNames).toEqual(["-json", "-sc", "-silent", "-td", "-title"])
  for (const f of httpx.command.flags) {
    expect(f.takes_value).not.toBe(true)
  }
})

test("nmap has NO target_flag (bare positional, like curl)", () => {
  const c = loadCatalog(catalogPath)
  const nmap = findTool(c, "nmap")
  expect(nmap.command.base).toBe("nmap")
  expect(nmap.command.target_flag).toBeUndefined()
  expect(nmap.category).toBe("recon")
  expect(nmap.phase).toEqual(["recon"])
  expect(nmap.requires_root).toBe(false)
})

test("nmap declares the expected boolean flags", () => {
  const c = loadCatalog(catalogPath)
  const nmap = findTool(c, "nmap")
  const flagNames = nmap.command.flags.map((f) => f.name).sort()
  // no stray flags beyond the ones the spec declares
  expect(flagNames).toEqual(["-Pn", "-T3", "-T4", "-oG", "-p", "-sT", "-sV"])
  for (const name of ["-sT", "-sV", "-Pn", "-T3", "-T4"]) {
    const f = flagByName(nmap, name)
    expect(f.takes_value).not.toBe(true)
  }
})

test("nmap -p takes a value with the exact port-range pattern", () => {
  const c = loadCatalog(catalogPath)
  const nmap = findTool(c, "nmap")
  const p = flagByName(nmap, "-p")
  expect(p.takes_value).toBe(true)
  expect(p.value_pattern).toBe(NMAP_PORT_PATTERN)
})

test("nmap -oG takes a value with the exact literal-dash pattern", () => {
  const c = loadCatalog(catalogPath)
  const nmap = findTool(c, "nmap")
  const oG = flagByName(nmap, "-oG")
  expect(oG.takes_value).toBe(true)
  expect(oG.value_pattern).toBe(NMAP_OG_PATTERN)
})

test("every recon value_pattern is fully anchored with ^ and $", () => {
  const c = loadCatalog(catalogPath)
  const recon = c.tools.filter((t) => t.category === "recon")
  const valuePatterns = recon.flatMap((t) =>
    (t.command.flags ?? []).filter((f) => f.takes_value).map((f) => f.value_pattern),
  )
  expect(valuePatterns.length).toBeGreaterThan(0)
  for (const pattern of valuePatterns) {
    expect(pattern.startsWith("^")).toBe(true)
    expect(pattern.endsWith("$")).toBe(true)
  }
})
