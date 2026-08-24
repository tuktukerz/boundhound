// test/dockerfile-enum.test.mjs
//
// Phase 2 enum (Task 4): docker/Dockerfile gains pinned ffuf + nuclei
// installs in the existing golang builder stage, both binaries copied into
// the final debian:stable-slim stage, and a bundled wordlist baked in at
// /usr/share/boundhound/wordlists/common.txt.
// This is a STATIC structural test: it reads the Dockerfile as text and
// asserts on its shape. It does NOT run `docker build` — the real image
// build + run happens in the later e2e task.
import { test, expect } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const dockerfilePath = join(import.meta.dir, "..", "docker", "Dockerfile")
const dockerfile = readFileSync(dockerfilePath, "utf8")

const wordlistPath = join(import.meta.dir, "..", "docker", "wordlists", "common.txt")

test("builder stage go-installs ffuf pinned to an exact version tag", () => {
  expect(/go install\s+github\.com\/ffuf\/ffuf\/v2@v\d+\.\d+\.\d+\b/.test(dockerfile)).toBe(true)
})

test("builder stage go-installs nuclei pinned to an exact version tag", () => {
  expect(
    /go install\s+github\.com\/projectdiscovery\/nuclei\/v3\/cmd\/nuclei@v\d+\.\d+\.\d+\b/.test(dockerfile),
  ).toBe(true)
})

test("final stage copies ffuf binary from the builder stage", () => {
  expect(/COPY --from=\S+\s+\/go\/bin\/ffuf\s+\/usr\/local\/bin\/ffuf/.test(dockerfile)).toBe(true)
})

test("final stage copies nuclei binary from the builder stage", () => {
  expect(/COPY --from=\S+\s+\/go\/bin\/nuclei\s+\/usr\/local\/bin\/nuclei/.test(dockerfile)).toBe(true)
})

test("final stage bakes the bundled wordlist into the image", () => {
  expect(
    /COPY\s+wordlists\/common\.txt\s+\/usr\/share\/boundhound\/wordlists\/common\.txt/.test(dockerfile),
  ).toBe(true)
})

test("Phase-1 recon tooling (subfinder/httpx/nmap) stays intact", () => {
  expect(/go install\s+github\.com\/projectdiscovery\/subfinder\/v2\/cmd\/subfinder@v2\.6\.6\b/.test(dockerfile)).toBe(
    true,
  )
  expect(/go install\s+github\.com\/projectdiscovery\/httpx\/cmd\/httpx@v1\.6\.9\b/.test(dockerfile)).toBe(true)
  expect(/\bnmap\b/.test(dockerfile)).toBe(true)
})

test("docker/wordlists/common.txt exists in-repo", () => {
  expect(() => readFileSync(wordlistPath, "utf8")).not.toThrow()
})

test("wordlist contains a line exactly 'index.html' (offline e2e fuzzes this against nginx)", () => {
  const lines = readFileSync(wordlistPath, "utf8").split("\n")
  expect(lines).toContain("index.html")
})

test("wordlist has no blank lines and no comment lines", () => {
  const raw = readFileSync(wordlistPath, "utf8")
  const lines = raw.split("\n").filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ""))
  for (const line of lines) {
    expect(line.trim().length).toBeGreaterThan(0)
    expect(line.startsWith("#")).toBe(false)
  }
})

test("wordlist has a reasonable number of entries (50-100)", () => {
  const raw = readFileSync(wordlistPath, "utf8")
  const lines = raw.split("\n").filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ""))
  expect(lines.length).toBeGreaterThanOrEqual(50)
  expect(lines.length).toBeLessThanOrEqual(100)
})
