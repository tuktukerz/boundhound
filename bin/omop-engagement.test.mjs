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
