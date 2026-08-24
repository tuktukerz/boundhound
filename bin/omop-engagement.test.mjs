import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createEngagement } from "./omop-engagement.mjs"

let root, upCalls
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "omop-eng-"))
  mkdirSync(join(root, "engagements", "templates"), { recursive: true })
  writeFileSync(join(root, "engagements", "templates", "scope.yaml"), "engagement: REPLACE_ME\n")
  upCalls = []
})

test("scaffolds engagement, sets .active, calls containerUp", () => {
  const { path } = createEngagement("acme", { rootDir: root, containerUp: (n) => upCalls.push(n) })
  expect(existsSync(join(path, "scope.yaml"))).toBe(true)
  expect(readFileSync(join(root, "engagements", ".active"), "utf8").trim()).toBe("acme")
  expect(upCalls).toEqual(["acme"])
})

test("does not overwrite an existing scope.yaml", () => {
  createEngagement("acme", { rootDir: root, containerUp: () => {} })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), "engagement: acme\nkeep: yes\n")
  createEngagement("acme", { rootDir: root, containerUp: () => {} })
  expect(readFileSync(join(root, "engagements", "acme", "scope.yaml"), "utf8")).toContain("keep: yes")
})

// P4: split codeDir/dataDir -> template read from codeDir, engagement
// (dir, scope.yaml, .active) written to dataDir. codeDir here holds ONLY
// the templates dir (no engagements/ at all) to prove the read never
// touches dataDir.
test("P4: split codeDir/dataDir -> template from codeDir, engagement written to dataDir", () => {
  const codeDir = mkdtempSync(join(tmpdir(), "omop-eng-code-"))
  mkdirSync(join(codeDir, "engagements", "templates"), { recursive: true })
  writeFileSync(join(codeDir, "engagements", "templates", "scope.yaml"), "engagement: REPLACE_ME\nfrom: codeDir\n")
  const dataDir = mkdtempSync(join(tmpdir(), "omop-eng-data-"))
  const upCalls = []

  const { path } = createEngagement("acme", { codeDir, dataDir, containerUp: (n) => upCalls.push(n) })

  expect(path).toBe(join(dataDir, "engagements", "acme"))
  expect(existsSync(join(dataDir, "engagements", "acme", "scope.yaml"))).toBe(true)
  expect(readFileSync(join(dataDir, "engagements", "acme", "scope.yaml"), "utf8")).toBe("engagement: acme\nfrom: codeDir\n")
  expect(readFileSync(join(dataDir, "engagements", ".active"), "utf8").trim()).toBe("acme")
  expect(upCalls).toEqual(["acme"])
})
