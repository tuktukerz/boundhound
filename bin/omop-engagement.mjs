import { join } from "node:path"
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { codeRoot, dataRoot } from "../src/paths.mjs"

export function createEngagement(name, { rootDir, codeDir, dataDir, containerUp } = {}) {
  const cDir = codeDir ?? rootDir ?? codeRoot()
  const dDir = dataDir ?? rootDir ?? dataRoot()
  const dir = join(dDir, "engagements", name)
  mkdirSync(join(dir, "output"), { recursive: true })
  const scopePath = join(dir, "scope.yaml")
  if (!existsSync(scopePath)) {
    const tpl = readFileSync(join(cDir, "engagements", "templates", "scope.yaml"), "utf8")
    writeFileSync(scopePath, tpl.replace("REPLACE_ME", name))
  }
  writeFileSync(join(dDir, "engagements", ".active"), name)
  const up = containerUp ?? ((n) => execFileSync("bin/omop-container", ["up", n], { stdio: "inherit" }))
  up(name)
  return { path: dir }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const name = process.argv[2]
  if (!name) { process.stderr.write("usage: omop-engagement <name>\n"); process.exit(1) }
  const { path } = createEngagement(name, {})
  process.stdout.write(`engagement ready: ${path}\nedit scope.yaml, then run tools via omop-exec.\n`)
}
