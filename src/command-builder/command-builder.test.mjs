import { test, expect } from "bun:test"
import { buildCommand } from "./command-builder.mjs"

const curl = {
  tools_name: "curl",
  command: { base: "curl", flags: [], positional: [{ name: "url", required: true }] },
}

test("builds base + extraArgs + target", () => {
  const argv = buildCommand(curl, { target: "https://api.acme.io", extraArgs: ["-I"] })
  expect(argv[0]).toBe("curl")
  expect(argv).toContain("-I")
  expect(argv[argv.length - 1]).toBe("https://api.acme.io")
})

test("throws when required positional target missing", () => {
  expect(() => buildCommand(curl, { extraArgs: [] })).toThrow(/target/)
})

const subfinder = {
  tools_name: "subfinder",
  command: { base: "subfinder", target_flag: "-d", flags: [], positional: [] },
}

test("renders target behind target_flag when declared", () => {
  const argv = buildCommand(subfinder, { target: "acme.io", extraArgs: ["-silent"] })
  expect(argv).toEqual(["subfinder", "-silent", "-d", "acme.io"])
})

test("bare-positional path is unchanged for entries without target_flag (nmap shape)", () => {
  const nmap = {
    tools_name: "nmap",
    command: { base: "nmap", flags: [], positional: [{ name: "target", required: true }] },
  }
  const argv = buildCommand(nmap, { target: "1.2.3.4", extraArgs: ["-sV"] })
  expect(argv).toEqual(["nmap", "-sV", "1.2.3.4"])
})

test("needsTarget is true when target_flag is set even with no required positional, and throws if target missing", () => {
  expect(() => buildCommand(subfinder, { extraArgs: [] })).toThrow(/target/)
})
