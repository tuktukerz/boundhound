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
