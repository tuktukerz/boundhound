// src/paths.test.mjs
import { test, expect, beforeEach, afterEach } from "bun:test"
import { mkdtempSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { codeRoot, dataRoot } from "./paths.mjs"

// Save original env values before each test
let savedEnv = {}

beforeEach(() => {
  savedEnv = {
    CLAUDE_PLUGIN_ROOT: process.env.CLAUDE_PLUGIN_ROOT,
    CLAUDE_PLUGIN_DATA: process.env.CLAUDE_PLUGIN_DATA,
    CLAUDE_PROJECT_DIR: process.env.CLAUDE_PROJECT_DIR,
  }
})

afterEach(() => {
  // Restore original env values
  if (savedEnv.CLAUDE_PLUGIN_ROOT === undefined) {
    delete process.env.CLAUDE_PLUGIN_ROOT
  } else {
    process.env.CLAUDE_PLUGIN_ROOT = savedEnv.CLAUDE_PLUGIN_ROOT
  }

  if (savedEnv.CLAUDE_PLUGIN_DATA === undefined) {
    delete process.env.CLAUDE_PLUGIN_DATA
  } else {
    process.env.CLAUDE_PLUGIN_DATA = savedEnv.CLAUDE_PLUGIN_DATA
  }

  if (savedEnv.CLAUDE_PROJECT_DIR === undefined) {
    delete process.env.CLAUDE_PROJECT_DIR
  } else {
    process.env.CLAUDE_PROJECT_DIR = savedEnv.CLAUDE_PROJECT_DIR
  }
})

// P1: codeRoot() returns CLAUDE_PLUGIN_ROOT when set, else repo root
test("codeRoot() returns CLAUDE_PLUGIN_ROOT when set", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "boundhound-plugin-"))
  process.env.CLAUDE_PLUGIN_ROOT = tempDir
  expect(codeRoot()).toBe(tempDir)
})

test("codeRoot() returns repo root when CLAUDE_PLUGIN_ROOT is unset", () => {
  delete process.env.CLAUDE_PLUGIN_ROOT
  const root = codeRoot()
  // Verify it's the repo root by checking for tools-catalog.json
  expect(existsSync(join(root, "tools-catalog.json"))).toBe(true)
})

// P2: dataRoot() precedence
test("dataRoot() returns CLAUDE_PLUGIN_DATA when set", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "boundhound-data-"))
  process.env.CLAUDE_PLUGIN_DATA = tempDir
  process.env.CLAUDE_PROJECT_DIR = "/some/other/path"
  expect(dataRoot()).toBe(tempDir)
})

test("dataRoot() returns CLAUDE_PROJECT_DIR when CLAUDE_PLUGIN_DATA is unset", () => {
  delete process.env.CLAUDE_PLUGIN_DATA
  const tempDir = mkdtempSync(join(tmpdir(), "boundhound-project-"))
  process.env.CLAUDE_PROJECT_DIR = tempDir
  expect(dataRoot()).toBe(tempDir)
})

test("dataRoot() returns cwd when both plugin and project env vars are unset", () => {
  delete process.env.CLAUDE_PLUGIN_DATA
  delete process.env.CLAUDE_PROJECT_DIR
  expect(dataRoot()).toBe(process.cwd())
})

test("dataRoot() precedence: PLUGIN_DATA > PROJECT_DIR > cwd", () => {
  const pluginDataDir = mkdtempSync(join(tmpdir(), "boundhound-plugin-data-"))
  const projectDir = mkdtempSync(join(tmpdir(), "boundhound-project-"))

  process.env.CLAUDE_PLUGIN_DATA = pluginDataDir
  process.env.CLAUDE_PROJECT_DIR = projectDir

  expect(dataRoot()).toBe(pluginDataDir)
})
