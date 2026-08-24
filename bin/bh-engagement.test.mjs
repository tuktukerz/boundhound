import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, existsSync, readFileSync, mkdirSync, writeFileSync, chmodSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createEngagement } from "./bh-engagement.mjs"

let root, upCalls
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-eng-"))
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
  const codeDir = mkdtempSync(join(tmpdir(), "bh-eng-code-"))
  mkdirSync(join(codeDir, "engagements", "templates"), { recursive: true })
  writeFileSync(join(codeDir, "engagements", "templates", "scope.yaml"), "engagement: REPLACE_ME\nfrom: codeDir\n")
  const dataDir = mkdtempSync(join(tmpdir(), "bh-eng-data-"))
  const upCalls = []

  const { path } = createEngagement("acme", { codeDir, dataDir, containerUp: (n) => upCalls.push(n) })

  expect(path).toBe(join(dataDir, "engagements", "acme"))
  expect(existsSync(join(dataDir, "engagements", "acme", "scope.yaml"))).toBe(true)
  expect(readFileSync(join(dataDir, "engagements", "acme", "scope.yaml"), "utf8")).toBe("engagement: acme\nfrom: codeDir\n")
  expect(readFileSync(join(dataDir, "engagements", ".active"), "utf8").trim()).toBe("acme")
  expect(upCalls).toEqual(["acme"])
})

// Fix 1 regression: the default containerUp (no containerUp override) used
// to shell out to a bare relative path ("bin/bh-container"), which Node
// resolves against process.cwd() — broken from any dir that isn't the repo
// checkout. It must instead be built from cDir (join(cDir, "bin",
// "bh-container")), the same code-root resolution runExec already uses
// for tools-catalog.json. Proven here with a real (fake) executable and a
// cwd deliberately different from cDir, and NOT the process's real cwd at
// test-run time — so a regression to the bare relative path would either
// fail to find the binary (ENOENT) or invoke the wrong one, not silently
// pass. No real Docker/bh-container involved.
test("Fix 1: default containerUp resolves the binary from cDir, not cwd", () => {
  const codeDir = mkdtempSync(join(tmpdir(), "bh-eng-code-"))
  mkdirSync(join(codeDir, "engagements", "templates"), { recursive: true })
  writeFileSync(join(codeDir, "engagements", "templates", "scope.yaml"), "engagement: REPLACE_ME\n")
  mkdirSync(join(codeDir, "bin"), { recursive: true })

  const marker = join(codeDir, "bin", "invoked.txt")
  const fakeContainerBin = join(codeDir, "bin", "bh-container")
  writeFileSync(fakeContainerBin, `#!/usr/bin/env bash\necho "$@" > "${marker}"\n`)
  chmodSync(fakeContainerBin, 0o755)

  const dataDir = mkdtempSync(join(tmpdir(), "bh-eng-data-"))
  // A foreign cwd, unrelated to codeDir/dataDir, proves resolution does not
  // depend on process.cwd() (which is what the bare-relative-path bug did).
  const foreignCwd = mkdtempSync(join(tmpdir(), "bh-eng-foreign-cwd-"))

  const originalCwd = process.cwd()
  process.chdir(foreignCwd)
  try {
    createEngagement("acme", { codeDir, dataDir })
  } finally {
    process.chdir(originalCwd)
  }

  expect(existsSync(marker)).toBe(true)
  expect(readFileSync(marker, "utf8").trim()).toBe("up acme")
})
