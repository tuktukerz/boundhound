// src/scope/active-engagement.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { loadActiveConfig, NoActiveEngagement } from "./active-engagement.mjs"

let root
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "bh-")) })

const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["*.acme.com"]
`

test("throws when no .active (fail-closed)", () => {
  expect(() => loadActiveConfig(root)).toThrow(NoActiveEngagement)
})

test("loads config for active engagement", () => {
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(root, "engagements", ".active"), "acme")
  const c = loadActiveConfig(root)
  expect(c.engagement).toBe("acme")
})

test("throws when scope.yaml missing (fail-closed)", () => {
  mkdirSync(join(root, "engagements"), { recursive: true })
  writeFileSync(join(root, "engagements", ".active"), "ghost")
  expect(() => loadActiveConfig(root)).toThrow()
})
