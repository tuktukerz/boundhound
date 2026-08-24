// src/safety/safety-check.test.mjs
import { test, expect } from "bun:test"
import { checkSafety } from "./safety-check.mjs"

const strict = { block_destructive: true, block_dos: true }
const off = { block_destructive: false, block_dos: false }

test("blocks destructive flag when block_destructive on", () => {
  const r = checkSafety("sqlmap", ["-u", "x", "--dump-all"], strict)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/destructive/)
})

test("blocks os-shell", () => {
  expect(checkSafety("sqlmap", ["--os-shell"], strict).decision).toBe("DENY")
})

test("blocks DoS-ish extreme threads when block_dos on", () => {
  expect(checkSafety("ffuf", ["-t", "5000"], strict).decision).toBe("DENY")
})

test("allows benign args", () => {
  expect(checkSafety("curl", ["-I"], strict).decision).toBe("ALLOW")
})

test("lab profile (all off) allows destructive", () => {
  expect(checkSafety("sqlmap", ["--dump-all"], off).decision).toBe("ALLOW")
})

test("DOS check catches --threads=<n> form", () => {
  expect(checkSafety("ffuf", ["--threads=5000"], strict).decision).toBe("DENY")
})

test("DOS check catches -t<n> glued form", () => {
  expect(checkSafety("ffuf", ["-t5000"], strict).decision).toBe("DENY")
})

test("blocks destructive flag case-insensitive", () => {
  expect(checkSafety("sqlmap", ["--DUMP-ALL"], strict).decision).toBe("DENY")
})

test("checkSafety treats null constraints as strict (deny-by-default)", () => {
  expect(checkSafety("sqlmap", ["--os-shell"], null).decision).toBe("DENY")
})

test("checkSafety treats undefined constraints as strict", () => {
  expect(checkSafety("sqlmap", ["--os-shell"], undefined).decision).toBe("DENY")
})
