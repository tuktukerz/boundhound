import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

// Where bundled code lives (tools-catalog.json, engagements/templates/): the
// plugin install dir when running as a plugin, else the repo root (computed
// from this module's own location) when running as a local project.
export function codeRoot() {
  if (process.env.CLAUDE_PLUGIN_ROOT) return process.env.CLAUDE_PLUGIN_ROOT
  return join(dirname(fileURLToPath(import.meta.url)), "..") // src/ -> repo root
}

// Where per-user state lives (engagements/, audit logs): persists across plugin
// updates. Falls back to project dir, then cwd, for local-project use.
export function dataRoot() {
  return process.env.CLAUDE_PLUGIN_DATA
    ?? process.env.CLAUDE_PROJECT_DIR
    ?? process.cwd()
}
