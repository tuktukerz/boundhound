// test/dockerfile-recon.test.mjs
//
// Phase 1 recon (Task 6): docker/Dockerfile becomes a multi-stage build —
// a golang builder stage compiles pinned subfinder/httpx, and the final
// debian:stable-slim stage apt-installs nmap and copies the Go binaries in.
// This is a STATIC structural test: it reads the Dockerfile as text and
// asserts on its shape. It does NOT run `docker build` — the real image
// build + run happens in the later e2e task.
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const dockerfilePath = join(import.meta.dir, "..", "docker", "Dockerfile")
const dockerfile = readFileSync(dockerfilePath, "utf8")

test("has a golang builder stage", () => {
  expect(/^FROM golang\S*\s+AS\s+\S+/m.test(dockerfile)).toBe(true)
})

test("builder stage go-installs subfinder with a pinned version", () => {
  expect(/go install\s+github\.com\/projectdiscovery\/subfinder\/v2\/cmd\/subfinder@v[\d.]+/.test(dockerfile)).toBe(
    true,
  )
})

test("builder stage go-installs httpx with a pinned version", () => {
  expect(/go install\s+github\.com\/projectdiscovery\/httpx\/cmd\/httpx@v[\d.]+/.test(dockerfile)).toBe(true)
})

test("final stage is debian:stable-slim", () => {
  expect(/^FROM debian:stable-slim\s*$/m.test(dockerfile)).toBe(true)
})

test("final stage apt-installs nmap", () => {
  const aptInstallMatch = dockerfile.match(/apt-get install[^\n]*(\n[^\n]*)*?\n\s*&&\s*rm -rf \/var\/lib\/apt\/lists/)
  expect(aptInstallMatch).not.toBeNull()
  expect(aptInstallMatch[0]).toMatch(/\bnmap\b/)
})

test("copies subfinder binary from the builder stage", () => {
  expect(/COPY --from=\S+\s+\/go\/bin\/subfinder\s+\/usr\/local\/bin\/subfinder/.test(dockerfile)).toBe(true)
})

test("copies httpx binary from the builder stage", () => {
  expect(/COPY --from=\S+\s+\/go\/bin\/httpx\s+\/usr\/local\/bin\/httpx/.test(dockerfile)).toBe(true)
})

test("no Indonesian sentinel words remain", () => {
  const indonesianWords = ["Fase", "HANYA", "TIDAK", "alat", "uji", "jembatan"]
  for (const word of indonesianWords) {
    expect(dockerfile).not.toMatch(new RegExp(`\\b${word}\\b`, "i"))
  }
})
