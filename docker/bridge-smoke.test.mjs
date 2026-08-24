import { test, expect } from "bun:test"
import { spawnSync, execFileSync } from "node:child_process"

function smokeContainerRunning() {
  const r = spawnSync("docker", ["inspect", "-f", "{{.State.Running}}", "bh-smoke"], { encoding: "utf8" })
  return r.status === 0 && r.stdout.trim() === "true"
}
const available = smokeContainerRunning()

// Integration test: only runs when the bh-smoke container is up; skipped otherwise
// so the default unit suite stays green without Docker.
test.skipIf(!available)("curl runs inside the container", () => {
  const out = execFileSync("docker", ["exec", "bh-smoke", "curl", "--version"], { encoding: "utf8" })
  expect(out).toMatch(/curl \d/)
})
