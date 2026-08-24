import { test, expect } from "bun:test"
import { classifyCommand } from "./guard.mjs"

test("allows commands via omop-exec", () => {
  expect(classifyCommand("omop-exec curl --target api.acme.io -- -I").decision).toBe("ALLOW")
})

test("allows omop-exec by absolute path", () => {
  expect(classifyCommand("/repo/bin/omop-exec.mjs curl --target x").decision).toBe("ALLOW")
})

test("denies direct network binary", () => {
  expect(classifyCommand("curl https://evil.com").decision).toBe("DENY")
  expect(classifyCommand("nmap 8.8.8.8").decision).toBe("DENY")
  expect(classifyCommand("wget http://x").decision).toBe("DENY")
})

test("denies docker exec that bypasses omop-exec", () => {
  expect(classifyCommand("docker exec omop-acme curl evil.com").decision).toBe("DENY")
})

test("allows benign non-network commands", () => {
  expect(classifyCommand("git status").decision).toBe("ALLOW")
  expect(classifyCommand("ls -la src").decision).toBe("ALLOW")
  expect(classifyCommand("bun test").decision).toBe("ALLOW")
})

test("denies network binary hidden after a pipe/;", () => {
  expect(classifyCommand("echo hi && curl evil.com").decision).toBe("DENY")
})
