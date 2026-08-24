// test/tools-catalog-enum.test.mjs
//
// Phase 2 enum (Task 2): tools-catalog.json gains ffuf/nuclei entries
// alongside the existing curl + recon (subfinder/httpx/nmap) entries. This
// is a static structural check on the catalog data itself (loads via the
// real loader, which fail-closed-rejects any takes_value flag whose
// value_pattern is not fully anchored — the Phase-1 loader invariant), not
// a behavioral test of command-builder/bh-exec (those have their own
// suites; ffuf/nuclei both ride the existing target_flag:"-u" pipeline
// unchanged, per spec §2.1).
import { test, expect } from "bun:test"
import { join } from "node:path"
import { loadCatalog, findTool } from "../src/catalog/catalog-loader.mjs"

const catalogPath = join(import.meta.dir, "..", "tools-catalog.json")

// Exact anchored patterns from spec §4 — the catalog entries must use these
// literals verbatim.
const FFUF_PATTERNS = {
  "-w": "^/[A-Za-z0-9._/-]+$",
  "-mc": "^[0-9]{3}(,[0-9]{3})*$",
  "-fc": "^[0-9]{3}(,[0-9]{3})*$",
  "-t": "^[0-9]+$",
  "-rate": "^[0-9]+$",
  "-of": "^(json|csv|md|html|ejson)$",
  "-o": "^/[A-Za-z0-9._/-]+$",
}
const FFUF_BOOLEAN_FLAGS = ["-s"]

const NUCLEI_PATTERNS = {
  "-t": "^[A-Za-z0-9._/-]+$",
  "-severity": "^[a-z]+(,[a-z]+)*$",
  "-tags": "^[a-z0-9,_-]+$",
  "-c": "^[0-9]+$",
  "-rl": "^[0-9]+$",
}
const NUCLEI_BOOLEAN_FLAGS = ["-jsonl", "-silent", "-disable-update-check"]

function flagByName(entry, name) {
  return entry.command.flags.find((f) => f.name === name)
}

test("catalog loads successfully with ffuf + nuclei present", () => {
  expect(() => loadCatalog(catalogPath)).not.toThrow()
})

test("curl and recon entries still load unchanged", () => {
  const c = loadCatalog(catalogPath)
  const curl = findTool(c, "curl")
  expect(curl).not.toBeNull()
  expect(curl.command.base).toBe("curl")
  expect(curl.category).toBe("utility")
  expect(findTool(c, "subfinder")).not.toBeNull()
  expect(findTool(c, "httpx")).not.toBeNull()
  expect(findTool(c, "nmap")).not.toBeNull()
})

test("catalog declares the enum category", () => {
  const c = loadCatalog(catalogPath)
  expect(c.categories).toContain("enum")
})

test("findTool returns ffuf and nuclei", () => {
  const c = loadCatalog(catalogPath)
  expect(findTool(c, "ffuf")).not.toBeNull()
  expect(findTool(c, "nuclei")).not.toBeNull()
})

test("ffuf targets via -u, phase enum, rootless", () => {
  const c = loadCatalog(catalogPath)
  const ffuf = findTool(c, "ffuf")
  expect(ffuf.command.base).toBe("ffuf")
  expect(ffuf.command.target_flag).toBe("-u")
  expect(ffuf.phase).toEqual(["enum"])
  expect(ffuf.requires_root).toBe(false)
})

test("nuclei targets via -u, phase enum, rootless", () => {
  const c = loadCatalog(catalogPath)
  const nuclei = findTool(c, "nuclei")
  expect(nuclei.command.base).toBe("nuclei")
  expect(nuclei.command.target_flag).toBe("-u")
  expect(nuclei.phase).toEqual(["enum"])
  expect(nuclei.requires_root).toBe(false)
})

test("ffuf declares the exact set of flags from spec §4 — no stray flags", () => {
  const c = loadCatalog(catalogPath)
  const ffuf = findTool(c, "ffuf")
  const flagNames = ffuf.command.flags.map((f) => f.name).sort()
  const expected = [...Object.keys(FFUF_PATTERNS), ...FFUF_BOOLEAN_FLAGS].sort()
  expect(flagNames).toEqual(expected)
})

test("nuclei declares the exact set of flags from spec §4 — no stray flags", () => {
  const c = loadCatalog(catalogPath)
  const nuclei = findTool(c, "nuclei")
  const flagNames = nuclei.command.flags.map((f) => f.name).sort()
  const expected = [...Object.keys(NUCLEI_PATTERNS), ...NUCLEI_BOOLEAN_FLAGS].sort()
  expect(flagNames).toEqual(expected)
})

test("ffuf value flags have the exact anchored value_pattern from spec §4", () => {
  const c = loadCatalog(catalogPath)
  const ffuf = findTool(c, "ffuf")
  for (const [name, pattern] of Object.entries(FFUF_PATTERNS)) {
    const f = flagByName(ffuf, name)
    expect(f.takes_value).toBe(true)
    expect(f.value_pattern).toBe(pattern)
  }
  for (const name of FFUF_BOOLEAN_FLAGS) {
    const f = flagByName(ffuf, name)
    expect(f.takes_value).not.toBe(true)
  }
})

test("nuclei value flags have the exact anchored value_pattern from spec §4", () => {
  const c = loadCatalog(catalogPath)
  const nuclei = findTool(c, "nuclei")
  for (const [name, pattern] of Object.entries(NUCLEI_PATTERNS)) {
    const f = flagByName(nuclei, name)
    expect(f.takes_value).toBe(true)
    expect(f.value_pattern).toBe(pattern)
  }
  for (const name of NUCLEI_BOOLEAN_FLAGS) {
    const f = flagByName(nuclei, name)
    expect(f.takes_value).not.toBe(true)
  }
})

test("every ffuf/nuclei value_pattern is fully anchored with ^ and $", () => {
  const c = loadCatalog(catalogPath)
  const enumTools = c.tools.filter((t) => t.tools_name === "ffuf" || t.tools_name === "nuclei")
  const valuePatterns = enumTools.flatMap((t) =>
    (t.command.flags ?? []).filter((f) => f.takes_value).map((f) => f.value_pattern),
  )
  expect(valuePatterns.length).toBeGreaterThan(0)
  for (const pattern of valuePatterns) {
    expect(pattern.startsWith("^")).toBe(true)
    expect(pattern.endsWith("$")).toBe(true)
  }
})

test("ffuf and nuclei are categorized/phased as enum", () => {
  const c = loadCatalog(catalogPath)
  const ffuf = findTool(c, "ffuf")
  const nuclei = findTool(c, "nuclei")
  expect(ffuf.category).toBe("enum")
  expect(nuclei.category).toBe("enum")
})
