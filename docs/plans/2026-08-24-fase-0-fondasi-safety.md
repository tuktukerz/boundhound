# Fase 0 — Fondasi & Safety: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bangun kerangka repo bergaya OmOP + lapisan safety yang benar-benar dipaksa (scope enforcement deny-by-default via hook Claude Code), tanpa satu pun tool serang.

**Architecture:** Logika inti (scope matcher, safety check, catalog loader, command-builder, guard, audit) ditulis sebagai modul **Node ESM `.mjs`** murni — tanpa build step, bisa di-`import` langsung oleh hook & CLI. Enforcement dua lapis: hook `PreToolUse` (cegah bypass) + `bin/bh-exec` (cek scope+safety sebenarnya sebelum `docker exec`). Semua tervalidasi lewat `bun test`.

**Tech Stack:** Node ESM (`.mjs`), `bun test`, YAML (`yaml` pkg), Docker CLI, Claude Code hooks & commands.

**Spec:** `docs/specs/2026-08-24-fase-0-fondasi-safety-design.md`

## Global Constraints

- **Deny-by-default.** Target tak cocok `in_scope` eksplisit → DENY. Ragu → DENY. (spec §3.1)
- **Fail-closed.** Engagement tak aktif / `scope.yaml` rusak → DENY semua. (spec §3.2)
- **Nol tool serang.** Fase 0 TIDAK memasang nmap/nuclei/sqlmap/dst. Hanya `curl` sebagai tool uji jembatan. (spec §1 Non-Tujuan)
- **Ikut pola OmOP.** Skill = frontmatter OmOP; tool = schema `ToolEntry`; command = format `<command-instruction>`. (spec §2)
- **Runtime = Node ESM `.mjs`, tes = `bun test`.** Tanpa build step. Hook di-run via `node`.
- **Timestamp diinjeksi**, bukan diambil di dalam fungsi murni (untuk testability & kejujuran audit). (spec §4.7)
- **out_of_scope menang** atas `in_scope`. (spec §4.2)

---

## File Structure

**Modul inti (`src/`)** — tiap file satu tanggung jawab:
- `src/scope/scope-parser.mjs` — parse + validasi `scope.yaml` (tolak wildcard TLD-level).
- `src/scope/scope-matcher.mjs` — `matchTarget(target, config)` → `{decision, reason}`.
- `src/scope/active-engagement.mjs` — resolve engagement aktif + load config (fail-closed).
- `src/safety/safety-check.mjs` — `checkSafety(tool, args, constraints)` → `{decision, reason}`.
- `src/catalog/catalog-loader.mjs` — load + validasi `tools-catalog.json` (schema `ToolEntry`).
- `src/command-builder/command-builder.mjs` — `buildCommand(entry, {target, extraArgs})` → `string[]`.
- `src/audit/audit-log.mjs` — `appendAudit(path, entry)`.
- `src/guard/guard.mjs` — `classifyCommand(cmd)` → `{decision, reason}` (dipakai hook).

**Runtime glue:**
- `hooks/scope-guard.mjs` — hook `PreToolUse`: stdin JSON → guard → output keputusan.
- `bin/bh-exec.mjs` — CLI eksekusi tool (scope+safety+audit → `docker exec`).
- `bin/bh-engagement.mjs` — scaffold engagement + set `.active` + container up.

**Konfigurasi / aset:**
- `package.json`, `.gitignore`, `tools-catalog.json`, `docker/Dockerfile`.
- `.claude/settings.json`, `.claude/commands/engagement.md`, `.claude/commands/mode.md`, `.claude/skills/pentest-mode/SKILL.md`.
- `engagements/templates/scope.yaml`.

---

### Task 1: Bootstrap tooling

**Files:**
- Create: `package.json`, `.gitignore`, `src/.gitkeep`
- Test: `src/sanity.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces: `bun test` yang jalan; konvensi `.mjs` + `bun:test`.

- [ ] **Step 1: Write the failing test**

```javascript
// src/sanity.test.mjs
import { test, expect } from "bun:test"

test("bun test harness works", () => {
  expect(1 + 1).toBe(2)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/sanity.test.mjs`
Expected: FAIL — belum ada `package.json`/deps (atau "cannot find module").

- [ ] **Step 3: Create package.json and .gitignore**

```json
// package.json
{
  "name": "boundhound",
  "version": "0.0.0",
  "type": "module",
  "private": true,
  "scripts": {
    "test": "bun test"
  },
  "dependencies": {
    "yaml": "^2.5.0"
  }
}
```

```gitignore
# .gitignore
node_modules/
engagements/*/output/
engagements/*/audit.log
engagements/.active
*.log
```

Run: `bun install`

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/sanity.test.mjs`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add package.json .gitignore bun.lock src/
git commit -m "chore: bootstrap bun test harness (Fase 0)"
```

---

### Task 2: Scope parser + validator

**Files:**
- Create: `src/scope/scope-parser.mjs`
- Test: `src/scope/scope-parser.test.mjs`

**Interfaces:**
- Consumes: `yaml` package.
- Produces: `parseScope(yamlString) -> ScopeConfig` (throws `ScopeError` on invalid). `ScopeConfig` = `{engagement, authorization, mode, scope_enforcement, in_scope:{domains:[],cidrs:[]}, out_of_scope:{domains:[],cidrs:[]}, safety_constraints:{block_destructive,block_dos}, rate_limit, notes}`.

- [ ] **Step 1: Write the failing test**

```javascript
// src/scope/scope-parser.test.mjs
import { test, expect } from "bun:test"
import { parseScope, ScopeError } from "./scope-parser.mjs"

const valid = `
engagement: acme
authorization: "HackerOne #1"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["*.acme.com"]
  cidrs: ["203.0.113.0/24"]
out_of_scope:
  domains: ["blog.acme.com"]
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
`

test("parses a valid scope.yaml", () => {
  const c = parseScope(valid)
  expect(c.engagement).toBe("acme")
  expect(c.scope_enforcement).toBe("strict")
  expect(c.in_scope.domains).toContain("*.acme.com")
  expect(c.safety_constraints.block_destructive).toBe(true)
})

test("rejects missing authorization", () => {
  expect(() => parseScope(`engagement: x\nmode: auto\nscope_enforcement: strict`))
    .toThrow(ScopeError)
})

test("rejects TLD-level wildcard", () => {
  const bad = `engagement: x\nauthorization: "y"\nmode: auto\nscope_enforcement: strict\nin_scope:\n  domains: ["*.com"]`
  expect(() => parseScope(bad)).toThrow(/wildcard/i)
})

test("rejects unknown scope_enforcement value", () => {
  const bad = `engagement: x\nauthorization: "y"\nmode: auto\nscope_enforcement: loose`
  expect(() => parseScope(bad)).toThrow(ScopeError)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/scope/scope-parser.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/scope/scope-parser.mjs
import { parse as parseYaml } from "yaml"

export class ScopeError extends Error {}

const ENFORCEMENT = new Set(["strict", "moderate", "none"])

function normList(x) {
  if (x == null) return []
  if (!Array.isArray(x)) throw new ScopeError("expected a list")
  return x.map(String)
}

function assertWildcardsSafe(domains) {
  for (const d of domains) {
    if (d === "*" || /^\*\.[^.]+$/.test(d)) {
      throw new ScopeError(`wildcard too broad (TLD-level): ${d}`)
    }
  }
}

export function parseScope(yamlString) {
  let raw
  try {
    raw = parseYaml(yamlString)
  } catch (e) {
    throw new ScopeError(`invalid YAML: ${e.message}`)
  }
  if (!raw || typeof raw !== "object") throw new ScopeError("empty scope")
  if (!raw.engagement) throw new ScopeError("missing engagement")
  if (!raw.authorization) throw new ScopeError("missing authorization")
  if (!ENFORCEMENT.has(raw.scope_enforcement)) {
    throw new ScopeError(`invalid scope_enforcement: ${raw.scope_enforcement}`)
  }
  const inScope = {
    domains: normList(raw.in_scope?.domains),
    cidrs: normList(raw.in_scope?.cidrs),
  }
  const outScope = {
    domains: normList(raw.out_of_scope?.domains),
    cidrs: normList(raw.out_of_scope?.cidrs),
  }
  assertWildcardsSafe(inScope.domains)
  return {
    engagement: String(raw.engagement),
    authorization: String(raw.authorization),
    mode: raw.mode ?? "auto",
    scope_enforcement: raw.scope_enforcement,
    in_scope: inScope,
    out_of_scope: outScope,
    safety_constraints: {
      block_destructive: raw.safety_constraints?.block_destructive ?? true,
      block_dos: raw.safety_constraints?.block_dos ?? true,
    },
    rate_limit: raw.rate_limit ?? null,
    notes: raw.notes ?? "",
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/scope/scope-parser.test.mjs`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/scope/scope-parser.mjs src/scope/scope-parser.test.mjs
git commit -m "feat(scope): parse + validate scope.yaml with wildcard guard"
```

---

### Task 3: Scope matcher (jantung safety)

**Files:**
- Create: `src/scope/scope-matcher.mjs`
- Test: `src/scope/scope-matcher.test.mjs`

**Interfaces:**
- Consumes: `ScopeConfig` dari Task 2.
- Produces: `matchTarget(target, config) -> {decision:"ALLOW"|"DENY", reason:string}`. `normalizeTarget(raw) -> string` (hostname/IP).

- [ ] **Step 1: Write the failing test**

```javascript
// src/scope/scope-matcher.test.mjs
import { test, expect } from "bun:test"
import { matchTarget, normalizeTarget } from "./scope-matcher.mjs"

const cfg = {
  in_scope: { domains: ["*.acme.com", "api.acme.io"], cidrs: ["203.0.113.0/24"] },
  out_of_scope: { domains: ["blog.acme.com"], cidrs: ["203.0.113.5/32"] },
}

test("normalizes url/port to hostname", () => {
  expect(normalizeTarget("https://api.acme.io:443/x?y=1")).toBe("api.acme.io")
  expect(normalizeTarget("api.acme.io")).toBe("api.acme.io")
})

test("in-scope wildcard domain -> ALLOW", () => {
  expect(matchTarget("a.acme.com", cfg).decision).toBe("ALLOW")
})

test("in-scope exact domain -> ALLOW", () => {
  expect(matchTarget("api.acme.io", cfg).decision).toBe("ALLOW")
})

test("in-scope CIDR -> ALLOW", () => {
  expect(matchTarget("203.0.113.9", cfg).decision).toBe("ALLOW")
})

test("out_of_scope wins over in_scope", () => {
  const r = matchTarget("blog.acme.com", cfg)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/out_of_scope/)
})

test("out_of_scope CIDR /32 -> DENY", () => {
  expect(matchTarget("203.0.113.5", cfg).decision).toBe("DENY")
})

test("unlisted target -> DENY deny-by-default", () => {
  const r = matchTarget("evil.com", cfg)
  expect(r.decision).toBe("DENY")
  expect(r.reason).toMatch(/deny-by-default/)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/scope/scope-matcher.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/scope/scope-matcher.mjs

export function normalizeTarget(raw) {
  let s = String(raw).trim()
  if (s.includes("://")) {
    try { s = new URL(s).hostname } catch { /* fall through */ }
  } else {
    s = s.split("/")[0]        // strip path
    s = s.split(":")[0]        // strip port
  }
  return s.toLowerCase()
}

function isIPv4(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s)
}

function ipToInt(ip) {
  return ip.split(".").reduce((acc, o) => (acc << 8) + (Number(o) & 255), 0) >>> 0
}

function inCidr(ip, cidr) {
  if (!isIPv4(ip)) return false
  const [net, bitsStr] = cidr.split("/")
  const bits = Number(bitsStr)
  if (!isIPv4(net) || !(bits >= 0 && bits <= 32)) return false
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (ipToInt(ip) & mask) === (ipToInt(net) & mask)
}

function domainMatches(host, rule) {
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(1)        // ".acme.com"
    return host.endsWith(suffix) && host.length > suffix.length
  }
  return host === rule
}

function matchesAny(host, { domains, cidrs }) {
  for (const d of domains) if (domainMatches(host, d)) return d
  if (isIPv4(host)) for (const c of cidrs) if (inCidr(host, c)) return c
  return null
}

export function matchTarget(target, config) {
  const host = normalizeTarget(target)
  const out = matchesAny(host, config.out_of_scope ?? { domains: [], cidrs: [] })
  if (out) return { decision: "DENY", reason: `out_of_scope:${out}` }
  const inn = matchesAny(host, config.in_scope ?? { domains: [], cidrs: [] })
  if (inn) return { decision: "ALLOW", reason: `in_scope:${inn}` }
  return { decision: "DENY", reason: "deny-by-default" }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/scope/scope-matcher.test.mjs`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/scope/scope-matcher.mjs src/scope/scope-matcher.test.mjs
git commit -m "feat(scope): deny-by-default matcher (domain/wildcard/CIDR, out_of_scope wins)"
```

---

### Task 4: Active engagement resolver (fail-closed)

**Files:**
- Create: `src/scope/active-engagement.mjs`
- Test: `src/scope/active-engagement.test.mjs`

**Interfaces:**
- Consumes: `parseScope` (Task 2).
- Produces: `loadActiveConfig(rootDir) -> ScopeConfig` (throws `NoActiveEngagement` / `ScopeError` on any problem — caller treats throw as fail-closed DENY). `activeName(rootDir) -> string|null`.

- [ ] **Step 1: Write the failing test**

```javascript
// src/scope/active-engagement.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { loadActiveConfig, NoActiveEngagement } from "./active-engagement.mjs"

let root
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "bh-")) })

const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["*.acme.com"]
`

test("throws when no .active (fail-closed)", () => {
  expect(() => loadActiveConfig(root)).toThrow(NoActiveEngagement)
})

test("loads config for active engagement", () => {
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(root, "engagements", ".active"), "acme")
  const c = loadActiveConfig(root)
  expect(c.engagement).toBe("acme")
})

test("throws when scope.yaml missing (fail-closed)", () => {
  writeFileSync(join(root, "engagements", ".active"), "ghost")
  mkdirSync(join(root, "engagements"), { recursive: true })
  expect(() => loadActiveConfig(root)).toThrow()
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/scope/active-engagement.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/scope/active-engagement.mjs
import { readFileSync } from "node:fs"
import { join } from "node:path"
import { parseScope } from "./scope-parser.mjs"

export class NoActiveEngagement extends Error {}

export function activeName(rootDir) {
  try {
    const n = readFileSync(join(rootDir, "engagements", ".active"), "utf8").trim()
    return n || null
  } catch {
    return null
  }
}

export function loadActiveConfig(rootDir) {
  const name = activeName(rootDir)
  if (!name) throw new NoActiveEngagement("no active engagement")
  const path = join(rootDir, "engagements", name, "scope.yaml")
  const text = readFileSync(path, "utf8") // throws if missing -> fail-closed
  return parseScope(text)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/scope/active-engagement.test.mjs`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/scope/active-engagement.mjs src/scope/active-engagement.test.mjs
git commit -m "feat(scope): fail-closed active-engagement resolver"
```

---

### Task 5: Safety-constraints checker

**Files:**
- Create: `src/safety/safety-check.mjs`
- Test: `src/safety/safety-check.test.mjs`

**Interfaces:**
- Consumes: `safety_constraints` object dari `ScopeConfig`.
- Produces: `checkSafety(tool, args, constraints) -> {decision:"ALLOW"|"DENY", reason:string}`. `args` = `string[]`.

- [ ] **Step 1: Write the failing test**

```javascript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/safety/safety-check.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/safety/safety-check.mjs

// Fase 0: aturan minimal & generik. Diperkaya per-fase saat tool masuk (spec §6).
const DESTRUCTIVE = [/--dump-all/, /--os-shell/, /--os-pwn/, /\brm\s+-rf\b/, /--flush-session/]
const DOS = [
  { flag: "-t", max: 500 },        // threads (ffuf/gobuster style)
  { flag: "--threads", max: 500 },
  { flag: "--rate", max: 10000 },
]

export function checkSafety(tool, args, constraints) {
  const joined = args.join(" ")
  if (constraints?.block_destructive) {
    for (const re of DESTRUCTIVE) {
      if (re.test(joined)) return { decision: "DENY", reason: `destructive:${re}` }
    }
  }
  if (constraints?.block_dos) {
    for (let i = 0; i < args.length; i++) {
      const rule = DOS.find((d) => d.flag === args[i])
      if (rule) {
        const val = Number(args[i + 1])
        if (Number.isFinite(val) && val > rule.max) {
          return { decision: "DENY", reason: `dos:${rule.flag}=${val}>${rule.max}` }
        }
      }
    }
  }
  return { decision: "ALLOW", reason: "safety-ok" }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/safety/safety-check.test.mjs`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/safety/safety-check.mjs src/safety/safety-check.test.mjs
git commit -m "feat(safety): destructive/DoS constraint checker"
```

---

### Task 6: Tools catalog loader (schema ToolEntry OmOP)

**Files:**
- Create: `src/catalog/catalog-loader.mjs`, `tools-catalog.json`
- Test: `src/catalog/catalog-loader.test.mjs`

**Interfaces:**
- Produces: `loadCatalog(path) -> {version, tools: ToolEntry[]}` (throws `CatalogError`). `findTool(catalog, name) -> ToolEntry|null`. `ToolEntry` mengikuti OmOP: `{tools_name, description, category, command:{base, flags:[], positional:[]}, phase:[], tags:[], requires_root, output_format:[]}`.

- [ ] **Step 1: Write the failing test**

```javascript
// src/catalog/catalog-loader.test.mjs
import { test, expect } from "bun:test"
import { join } from "node:path"
import { loadCatalog, findTool, CatalogError } from "./catalog-loader.mjs"

const catalogPath = join(import.meta.dir, "..", "..", "tools-catalog.json")

test("loads the repo catalog", () => {
  const c = loadCatalog(catalogPath)
  expect(Array.isArray(c.tools)).toBe(true)
})

test("catalog contains the curl test tool", () => {
  const c = loadCatalog(catalogPath)
  const curl = findTool(c, "curl")
  expect(curl).not.toBeNull()
  expect(curl.command.base).toBe("curl")
  expect(curl.category).toBe("utility")
})

test("rejects a tool entry missing required fields", () => {
  const bad = JSON.stringify({ version: "1", tools: [{ tools_name: "x" }] })
  expect(() => loadCatalog(null, bad)).toThrow(CatalogError)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/catalog/catalog-loader.test.mjs`
Expected: FAIL — module/catalog not found.

- [ ] **Step 3: Create the catalog + implementation**

```json
// tools-catalog.json
{
  "$schema": "./docs/tools-catalog.schema.json",
  "version": "0.0.0",
  "categories": ["utility"],
  "tools": [
    {
      "tools_name": "curl",
      "description": "HTTP client — Fase 0 bridge test tool only",
      "category": "utility",
      "command": {
        "base": "curl",
        "flags": [
          { "name": "-sS", "type": "boolean", "description": "silent + show errors" },
          { "name": "-I", "type": "boolean", "description": "headers only" }
        ],
        "positional": [
          { "name": "url", "type": "string", "description": "target url", "required": true }
        ]
      },
      "installation": { "linux": { "command": "apt-get install -y curl", "manager": "apt" } },
      "check_installed": { "command": "curl --version", "exit_code": 0 },
      "skills_loader": "",
      "phase": ["utility"],
      "tags": ["http", "bridge-test"],
      "requires_root": false,
      "output_format": ["text"]
    }
  ]
}
```

```javascript
// src/catalog/catalog-loader.mjs
import { readFileSync } from "node:fs"

export class CatalogError extends Error {}

const REQUIRED = ["tools_name", "description", "category", "command", "phase"]

function validateEntry(e) {
  for (const k of REQUIRED) {
    if (e[k] == null) throw new CatalogError(`tool missing '${k}': ${JSON.stringify(e).slice(0, 80)}`)
  }
  if (!e.command.base) throw new CatalogError(`tool '${e.tools_name}' missing command.base`)
}

export function loadCatalog(path, rawOverride) {
  let raw
  try {
    raw = rawOverride ?? readFileSync(path, "utf8")
  } catch (e) {
    throw new CatalogError(`cannot read catalog: ${e.message}`)
  }
  let parsed
  try { parsed = JSON.parse(raw) } catch (e) { throw new CatalogError(`invalid JSON: ${e.message}`) }
  if (!Array.isArray(parsed.tools)) throw new CatalogError("catalog.tools must be an array")
  for (const e of parsed.tools) validateEntry(e)
  return parsed
}

export function findTool(catalog, name) {
  return catalog.tools.find((t) => t.tools_name === name) ?? null
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/catalog/catalog-loader.test.mjs`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/catalog/ tools-catalog.json
git commit -m "feat(catalog): tools-catalog.json loader (ToolEntry schema) + curl test tool"
```

---

### Task 7: Command-builder

**Files:**
- Create: `src/command-builder/command-builder.mjs`
- Test: `src/command-builder/command-builder.test.mjs`

**Interfaces:**
- Consumes: `ToolEntry` (Task 6).
- Produces: `buildCommand(entry, {target, extraArgs}) -> string[]` (argv, dimulai dari `command.base`).

- [ ] **Step 1: Write the failing test**

```javascript
// src/command-builder/command-builder.test.mjs
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/command-builder/command-builder.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/command-builder/command-builder.mjs

export function buildCommand(entry, { target, extraArgs = [] } = {}) {
  const needsTarget = (entry.command.positional ?? []).some((p) => p.required)
  if (needsTarget && !target) throw new Error("required positional target missing")
  const argv = [entry.command.base, ...extraArgs]
  if (target) argv.push(target)
  return argv
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/command-builder/command-builder.test.mjs`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/command-builder/
git commit -m "feat(command-builder): minimal argv builder from ToolEntry"
```

---

### Task 8: Audit log writer

**Files:**
- Create: `src/audit/audit-log.mjs`
- Test: `src/audit/audit-log.test.mjs`

**Interfaces:**
- Produces: `appendAudit(logPath, {ts, target, tool, decision, reason, authorization})` (append satu baris JSON). `ts` diinjeksi caller.

- [ ] **Step 1: Write the failing test**

```javascript
// src/audit/audit-log.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { appendAudit } from "./audit-log.mjs"

let dir
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "bh-audit-")) })

test("appends a JSON line with all fields", () => {
  const p = join(dir, "audit.log")
  appendAudit(p, { ts: "2026-08-24T00:00:00Z", target: "api.acme.io", tool: "curl", decision: "ALLOW", reason: "in_scope", authorization: "H1 #1" })
  appendAudit(p, { ts: "2026-08-24T00:00:01Z", target: "evil.com", tool: "curl", decision: "DENY", reason: "deny-by-default", authorization: "H1 #1" })
  const lines = readFileSync(p, "utf8").trim().split("\n")
  expect(lines.length).toBe(2)
  const first = JSON.parse(lines[0])
  expect(first.decision).toBe("ALLOW")
  expect(first.authorization).toBe("H1 #1")
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/audit/audit-log.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/audit/audit-log.mjs
import { appendFileSync } from "node:fs"

export function appendAudit(logPath, entry) {
  const line = JSON.stringify({
    ts: entry.ts,
    target: entry.target,
    tool: entry.tool,
    decision: entry.decision,
    reason: entry.reason,
    authorization: entry.authorization ?? null,
  })
  appendFileSync(logPath, line + "\n")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/audit/audit-log.test.mjs`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add src/audit/
git commit -m "feat(audit): append-only JSONL audit log"
```

---

### Task 9: Guard — bash command classifier (anti-bypass)

**Files:**
- Create: `src/guard/guard.mjs`
- Test: `src/guard/guard.test.mjs`

**Interfaces:**
- Produces: `classifyCommand(cmd) -> {decision:"ALLOW"|"DENY", reason}`. ALLOW jika perintah lewat `bh-exec` atau non-jaringan; DENY jika binari jaringan langsung atau `docker exec` bukan via `bh-exec`.

- [ ] **Step 1: Write the failing test**

```javascript
// src/guard/guard.test.mjs
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test src/guard/guard.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// src/guard/guard.mjs

const NETWORK_BINS = [
  "curl", "wget", "nc", "ncat", "netcat", "nmap", "masscan", "naabu",
  "ping", "telnet", "ssh", "ftp", "nuclei", "httpx", "ffuf", "gobuster",
  "sqlmap", "nikto", "subfinder", "amass", "katana", "dalfox",
]

function isBhExec(token) {
  return token === "bh-exec" || /(^|\/)bh-exec(\.mjs)?$/.test(token)
}

export function classifyCommand(cmd) {
  const text = String(cmd).trim()
  // Split into sub-commands on shell separators to catch chained bypass.
  const parts = text.split(/(?:&&|\|\||;|\|)/).map((p) => p.trim()).filter(Boolean)
  for (const part of parts) {
    const tokens = part.split(/\s+/)
    const head = tokens[0] ?? ""
    if (isBhExec(head)) continue // sanctioned path
    // docker exec bypass
    if (head === "docker" && tokens[1] === "exec") {
      return { decision: "DENY", reason: "docker-exec bypass (use bh-exec)" }
    }
    // direct network binary anywhere as a command head
    const base = head.split("/").pop()
    if (NETWORK_BINS.includes(base)) {
      return { decision: "DENY", reason: `direct network tool '${base}' (use bh-exec)` }
    }
  }
  return { decision: "ALLOW", reason: "non-network-or-sanctioned" }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test src/guard/guard.test.mjs`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add src/guard/
git commit -m "feat(guard): classify bash commands, deny direct network + docker-exec bypass"
```

---

### Task 10: `scope-guard.mjs` hook + settings.json registration

**Files:**
- Create: `hooks/scope-guard.mjs`, `.claude/settings.json`
- Test: `hooks/scope-guard.test.mjs`

**Interfaces:**
- Consumes: `classifyCommand` (Task 9).
- Produces: hook membaca JSON `PreToolUse` dari stdin, menulis JSON keputusan ke stdout sesuai protokol Claude Code.

> **Verifikasi protokol dulu:** cek format output hook `PreToolUse` di docs resmi Claude Code (`permissionDecision: "allow"|"deny"` di dalam `hookSpecificOutput`). Jika berbeda, sesuaikan `emit()`.

- [ ] **Step 1: Write the failing test**

```javascript
// hooks/scope-guard.test.mjs
import { test, expect } from "bun:test"
import { decideFromEvent } from "./scope-guard.mjs"

test("non-Bash tool -> allow (not our concern)", () => {
  const out = decideFromEvent({ tool_name: "Read", tool_input: {} })
  expect(out.hookSpecificOutput.permissionDecision).toBe("allow")
})

test("Bash direct curl -> deny", () => {
  const out = decideFromEvent({ tool_name: "Bash", tool_input: { command: "curl https://evil.com" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
})

test("Bash via bh-exec -> allow", () => {
  const out = decideFromEvent({ tool_name: "Bash", tool_input: { command: "bh-exec curl --target x" } })
  expect(out.hookSpecificOutput.permissionDecision).toBe("allow")
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test hooks/scope-guard.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write hook + register in settings.json**

```javascript
// hooks/scope-guard.mjs
import { classifyCommand } from "../src/guard/guard.mjs"

export function decideFromEvent(event) {
  const mk = (decision, reason) => ({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,     // "allow" | "deny"
      permissionDecisionReason: reason,
    },
  })
  if (event.tool_name !== "Bash") return mk("allow", "not-bash")
  const cmd = event.tool_input?.command ?? ""
  const r = classifyCommand(cmd)
  return mk(r.decision === "ALLOW" ? "allow" : "deny", r.reason)
}

// CLI entry: read stdin JSON, emit decision. Only runs when executed directly.
if (import.meta.main) {
  let input = ""
  process.stdin.setEncoding("utf8")
  for await (const chunk of process.stdin) input += chunk
  let event = {}
  try { event = JSON.parse(input || "{}") } catch { /* fail-closed below */ }
  const out = event.tool_name
    ? decideFromEvent(event)
    : { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "unparseable hook event (fail-closed)" } }
  process.stdout.write(JSON.stringify(out))
}
```

```json
// .claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "node \"$CLAUDE_PROJECT_DIR/hooks/scope-guard.mjs\"" }
        ]
      }
    ]
  }
}
```

> Note: `import.meta.main` didukung Bun & Node ≥20.10. Jika Node target lebih lama, ganti dengan cek `process.argv[1]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test hooks/scope-guard.test.mjs`
Expected: PASS (3 tests).

- [ ] **Step 5: Manual smoke test of stdin path**

Run: `echo '{"tool_name":"Bash","tool_input":{"command":"curl https://evil.com"}}' | node hooks/scope-guard.mjs`
Expected: JSON with `"permissionDecision":"deny"`.

- [ ] **Step 6: Commit**

```bash
git add hooks/ .claude/settings.json
git commit -m "feat(hook): PreToolUse scope-guard + settings.json registration"
```

---

### Task 11: `bin/bh-exec.mjs` (choke point eksekusi)

**Files:**
- Create: `bin/bh-exec.mjs`
- Test: `bin/bh-exec.test.mjs`

**Interfaces:**
- Consumes: Tasks 3,4,5,6,7,8.
- Produces: `runExec(argv, {rootDir, now, exec}) -> {code, message}`. `argv` = args setelah `bh-exec` (mis. `["curl","--target","api.acme.io","--","-I"]`). `exec(cmdArray)` diinjeksi (default `docker exec`); `now()` diinjeksi. Exit codes: 0 ALLOW, 2 DENY, 3 fail-closed.

- [ ] **Step 1: Write the failing test**

```javascript
// bin/bh-exec.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runExec } from "./bh-exec.mjs"

let root, calls
const now = () => "2026-08-24T00:00:00Z"
const exec = (arr) => { calls.push(arr); return 0 }

function setup(scope) {
  root = mkdtempSync(join(tmpdir(), "bh-exec-"))
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(root, "engagements", ".active"), "acme")
  // catalog: copy the repo's for curl
  writeFileSync(join(root, "tools-catalog.json"), JSON.stringify({
    version: "0", tools: [{ tools_name: "curl", description: "d", category: "utility",
      command: { base: "curl", flags: [], positional: [{ name: "url", required: true }] }, phase: ["utility"] }]
  }))
  calls = []
}

const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: ["api.acme.io"]
out_of_scope:
  domains: ["blog.acme.com"]
safety_constraints: { block_destructive: true, block_dos: true }
`

beforeEach(() => setup(scope))

test("in-scope target -> exec + exit 0", () => {
  const r = runExec(["curl", "--target", "api.acme.io", "--", "-I"], { rootDir: root, now, exec })
  expect(r.code).toBe(0)
  expect(calls.length).toBe(1)
  expect(calls[0]).toContain("api.acme.io")
})

test("out-of-scope target -> DENY exit 2, no exec", () => {
  const r = runExec(["curl", "--target", "evil.com", "--"], { rootDir: root, now, exec })
  expect(r.code).toBe(2)
  expect(calls.length).toBe(0)
})

test("destructive arg -> DENY exit 2", () => {
  const r = runExec(["curl", "--target", "api.acme.io", "--", "--os-shell"], { rootDir: root, now, exec })
  expect(r.code).toBe(2)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test bin/bh-exec.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```javascript
// bin/bh-exec.mjs
import { join } from "node:path"
import { execFileSync } from "node:child_process"
import { loadActiveConfig, activeName } from "../src/scope/active-engagement.mjs"
import { matchTarget } from "../src/scope/scope-matcher.mjs"
import { checkSafety } from "../src/safety/safety-check.mjs"
import { loadCatalog, findTool } from "../src/catalog/catalog-loader.mjs"
import { buildCommand } from "../src/command-builder/command-builder.mjs"
import { appendAudit } from "../src/audit/audit-log.mjs"

// argv: [tool, "--target", <t>, "--", ...extraArgs]
function parse(argv) {
  const tool = argv[0]
  const ti = argv.indexOf("--target")
  const target = ti >= 0 ? argv[ti + 1] : null
  const dd = argv.indexOf("--")
  const extraArgs = dd >= 0 ? argv.slice(dd + 1) : []
  return { tool, target, extraArgs }
}

const dockerExec = (name, cmdArray) =>
  execFileSync("docker", ["exec", name, ...cmdArray], { stdio: "inherit" })

export function runExec(argv, { rootDir, now, exec } = {}) {
  const runner = exec ?? ((cmdArray) => dockerExec(`bh-${cfgName}`, cmdArray))
  const stamp = (now ?? (() => new Date().toISOString()))()
  let cfg, cfgName
  try {
    cfg = loadActiveConfig(rootDir)
    cfgName = activeName(rootDir)
  } catch (e) {
    return { code: 3, message: `fail-closed: ${e.message}` }
  }
  const { tool, target, extraArgs } = parse(argv)
  const auditPath = join(rootDir, "engagements", cfgName, "audit.log")
  const deny = (reason) => {
    appendAudit(auditPath, { ts: stamp, target, tool, decision: "DENY", reason, authorization: cfg.authorization })
    return { code: 2, message: `DENY ${reason}` }
  }

  if (!target) return deny("missing --target")
  if (cfg.scope_enforcement !== "none") {
    const m = matchTarget(target, cfg)
    if (m.decision === "DENY") return deny(m.reason)
  }
  const s = checkSafety(tool, extraArgs, cfg.safety_constraints)
  if (s.decision === "DENY") return deny(s.reason)

  const catalog = loadCatalog(join(rootDir, "tools-catalog.json"))
  const entry = findTool(catalog, tool)
  if (!entry) return deny(`unknown tool '${tool}'`)
  const cmdArray = buildCommand(entry, { target, extraArgs })

  appendAudit(auditPath, { ts: stamp, target, tool, decision: "ALLOW", reason: "passed", authorization: cfg.authorization })
  const code = runner(cmdArray) ?? 0
  return { code: typeof code === "number" ? code : 0, message: "ALLOW" }
}

if (import.meta.main) {
  const r = runExec(process.argv.slice(2), { rootDir: process.env.CLAUDE_PROJECT_DIR ?? process.cwd() })
  if (r.message) process.stderr.write(r.message + "\n")
  process.exit(r.code)
}
```

> Note: perbaiki closure `cfgName` di default runner — set `cfgName` sebelum mendefinisikan `runner`, atau pindahkan default runner ke dalam blok setelah `cfgName` diketahui. Test menyuntik `exec`, jadi jalur default tidak diuji unit; rapikan saat Step 3.

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test bin/bh-exec.test.mjs`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add bin/bh-exec.mjs bin/bh-exec.test.mjs
git commit -m "feat(exec): bh-exec choke point (scope+safety+audit -> docker exec)"
```

---

### Task 12: `bin/bh-engagement.mjs` + scope template

**Files:**
- Create: `bin/bh-engagement.mjs`, `engagements/templates/scope.yaml`
- Test: `bin/bh-engagement.test.mjs`

**Interfaces:**
- Produces: `createEngagement(name, {rootDir, containerUp}) -> {path}`. Menulis `engagements/<name>/scope.yaml` dari template (jika belum ada), set `engagements/.active`, panggil `containerUp(name)` (diinjeksi; default = `bh-container up`).

- [ ] **Step 1: Write the failing test**

```javascript
// bin/bh-engagement.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, existsSync, readFileSync, mkdirSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createEngagement } from "./bh-engagement.mjs"

let root, upCalls
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-eng-"))
  mkdirSync(join(root, "engagements", "templates"), { recursive: true })
  writeFileSync(join(root, "engagements", "templates", "scope.yaml"), "engagement: REPLACE_ME\n")
  upCalls = []
})

test("scaffolds engagement, sets .active, calls containerUp", () => {
  const { path } = createEngagement("acme", { rootDir: root, containerUp: (n) => upCalls.push(n) })
  expect(existsSync(join(path, "scope.yaml"))).toBe(true)
  expect(readFileSync(join(root, "engagements", ".active"), "utf8").trim()).toBe("acme")
  expect(upCalls).toEqual(["acme"])
})

test("does not overwrite an existing scope.yaml", () => {
  createEngagement("acme", { rootDir: root, containerUp: () => {} })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), "engagement: acme\nkeep: yes\n")
  createEngagement("acme", { rootDir: root, containerUp: () => {} })
  expect(readFileSync(join(root, "engagements", "acme", "scope.yaml"), "utf8")).toContain("keep: yes")
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bun test bin/bh-engagement.test.mjs`
Expected: FAIL — module not found.

- [ ] **Step 3: Write template + implementation**

```yaml
# engagements/templates/scope.yaml
engagement: REPLACE_ME
authorization: "REPLACE_ME — bukti izin (H1/Bugcrowd/kontrak/lab)"
mode: bug-bounty
scope_enforcement: strict
in_scope:
  domains: []
  cidrs: []
out_of_scope:
  domains: []
  cidrs: []
safety_constraints:
  block_destructive: true
  block_dos: true
rate_limit: 10
notes: ""
```

```javascript
// bin/bh-engagement.mjs
import { join } from "node:path"
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { execFileSync } from "node:child_process"

export function createEngagement(name, { rootDir, containerUp } = {}) {
  const dir = join(rootDir, "engagements", name)
  mkdirSync(join(dir, "output"), { recursive: true })
  const scopePath = join(dir, "scope.yaml")
  if (!existsSync(scopePath)) {
    const tpl = readFileSync(join(rootDir, "engagements", "templates", "scope.yaml"), "utf8")
    writeFileSync(scopePath, tpl.replace("REPLACE_ME", name))
  }
  writeFileSync(join(rootDir, "engagements", ".active"), name)
  const up = containerUp ?? ((n) => execFileSync("bin/bh-container", ["up", n], { stdio: "inherit" }))
  up(name)
  return { path: dir }
}

if (import.meta.main) {
  const name = process.argv[2]
  if (!name) { process.stderr.write("usage: bh-engagement <name>\n"); process.exit(1) }
  const { path } = createEngagement(name, { rootDir: process.env.CLAUDE_PROJECT_DIR ?? process.cwd() })
  process.stdout.write(`engagement ready: ${path}\nedit scope.yaml, then run tools via bh-exec.\n`)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bun test bin/bh-engagement.test.mjs`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add bin/bh-engagement.mjs engagements/templates/
git commit -m "feat(engagement): scaffold engagement + scope template + set active"
```

---

### Task 13: Docker foundation + container lifecycle

**Files:**
- Create: `docker/Dockerfile`, `bin/bh-container`
- Test: `docker/bridge-smoke.test.mjs` (integration; butuh Docker)

**Interfaces:**
- Produces: image `boundhound:base`; `bin/bh-container up|down|status <name>`.

- [ ] **Step 1: Write the failing integration test**

```javascript
// docker/bridge-smoke.test.mjs
import { test, expect } from "bun:test"
import { execFileSync } from "node:child_process"

// Requires: docker available + image built + container bh-smoke up.
test("curl runs inside the container", () => {
  const out = execFileSync("docker", ["exec", "bh-smoke", "curl", "--version"], { encoding: "utf8" })
  expect(out).toMatch(/curl \d/)
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `bun test docker/bridge-smoke.test.mjs`
Expected: FAIL — image/container tidak ada.

- [ ] **Step 3: Write Dockerfile + lifecycle script**

```dockerfile
# docker/Dockerfile
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl iputils-ping dnsutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Fase 0: HANYA alat uji jembatan. TIDAK ada tool pentest.
WORKDIR /work
CMD ["sleep", "infinity"]
```

```bash
#!/usr/bin/env bash
# bin/bh-container
set -euo pipefail
action="${1:-}"; name="${2:-default}"; cname="bh-${name}"
case "$action" in
  up)
    docker image inspect boundhound:base >/dev/null 2>&1 || \
      docker build -t boundhound:base "$(dirname "$0")/../docker"
    docker inspect "$cname" >/dev/null 2>&1 || \
      docker run -d --name "$cname" boundhound:base >/dev/null
    echo "container up: $cname" ;;
  down) docker rm -f "$cname" >/dev/null 2>&1 || true; echo "down: $cname" ;;
  status) docker inspect -f '{{.State.Status}}' "$cname" 2>/dev/null || echo "absent" ;;
  *) echo "usage: bh-container up|down|status <name>"; exit 1 ;;
esac
```

Run: `chmod +x bin/bh-container`

- [ ] **Step 4: Build + bring up smoke container, run test**

```bash
bin/bh-container up smoke
bun test docker/bridge-smoke.test.mjs
bin/bh-container down smoke
```
Expected: test PASS.

- [ ] **Step 5: Commit**

```bash
git add docker/Dockerfile bin/bh-container docker/bridge-smoke.test.mjs
git commit -m "feat(docker): lean base image + container lifecycle + bridge smoke test"
```

---

### Task 14: Commands + `pentest-mode` skill (panen dari OmOP)

**Files:**
- Create: `.claude/commands/engagement.md`, `.claude/commands/mode.md`, `.claude/skills/pentest-mode/SKILL.md`
- Modify: (harvest) copy `skills-library/pentest-mode/SKILL.md` dari OmOP terlebih dulu

**Interfaces:**
- Produces: slash command `/engagement`, `/mode`; skill aktif `pentest-mode` (di-tuning ke config kita).

- [ ] **Step 1: Harvest the source skill into the library**

```bash
mkdir -p skills-library/pentest-mode
curl -s "https://raw.githubusercontent.com/zakirkun/oh-my-open-pentest/HEAD/.agents/skills/pentest-mode/SKILL.md" \
  -o skills-library/pentest-mode/SKILL.md
test -s skills-library/pentest-mode/SKILL.md && echo OK
```

- [ ] **Step 2: Write the command files (format OmOP)**

```markdown
<!-- .claude/commands/engagement.md -->
---
description: Mulai engagement pentest baru — isi scope, set aktif, nyalakan container
---

<command-instruction>
Load and follow the `pentest-mode` skill.

1. Tanyakan ke user: nama engagement, authorization (bukti izin), mode, dan daftar in_scope/out_of_scope.
2. Jalankan: `node bin/bh-engagement.mjs <nama>`
3. Tulis jawaban user ke `engagements/<nama>/scope.yaml` (ikuti template).
4. Ingatkan: semua tool HANYA boleh dijalankan lewat `bh-exec`.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
```

```markdown
<!-- .claude/commands/mode.md -->
---
description: Set engagement mode + scope_enforcement pada engagement aktif
---

<command-instruction>
Load and follow the `pentest-mode` skill. Update `mode` dan `scope_enforcement`
pada `engagements/<aktif>/scope.yaml` sesuai argumen (auto|ctf|bug-bounty|red-team|blue-team|offensive|grey-hat).
Jangan pernah set `scope_enforcement: none` untuk target selain lab/CTF milik sendiri.
</command-instruction>

<user-request>
$ARGUMENTS
</user-request>
```

- [ ] **Step 3: Tune the harvested skill into the active skill**

Copy `skills-library/pentest-mode/SKILL.md` → `.claude/skills/pentest-mode/SKILL.md`, lalu edit frontmatter + body agar cocok dengan config kita: referensi `scope.yaml` (bukan config OpenCode), `scope_enforcement` di-*enforce* hook, dan skill-chain diarahkan ke fase kita. Pertahankan format frontmatter OmOP (`name`, `description`+`Triggers:`, `phase`, `category`, `tags`).

- [ ] **Step 4: Verify skill is well-formed**

```bash
head -12 .claude/skills/pentest-mode/SKILL.md   # frontmatter valid: name + description
grep -q "scope.yaml" .claude/skills/pentest-mode/SKILL.md && echo "tuned OK"
```
Expected: frontmatter tampil, "tuned OK".

- [ ] **Step 5: Commit**

```bash
git add .claude/commands/ .claude/skills/pentest-mode/ skills-library/pentest-mode/
git commit -m "feat(commands): /engagement + /mode + tuned pentest-mode skill"
```

---

### Task 15: End-to-end acceptance suite (spec §5 T1–T12)

**Files:**
- Create: `test/acceptance.test.mjs`

**Interfaces:**
- Consumes: seluruh sistem. Memvalidasi kriteria penerimaan spec.

- [ ] **Step 1: Write the acceptance tests**

```javascript
// test/acceptance.test.mjs
import { test, expect, beforeEach } from "bun:test"
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runExec } from "../bin/bh-exec.mjs"
import { classifyCommand } from "../src/guard/guard.mjs"

let root, calls
const now = () => "2026-08-24T00:00:00Z"
const exec = (arr) => { calls.push(arr); return 0 }
const scope = `engagement: acme
authorization: "H1 #1"
mode: bug-bounty
scope_enforcement: strict
in_scope: { domains: ["api.acme.io", "*.acme.com"], cidrs: ["203.0.113.0/24"] }
out_of_scope: { domains: ["blog.acme.com"], cidrs: [] }
safety_constraints: { block_destructive: true, block_dos: true }
`
function catalog() {
  return JSON.stringify({ version: "0", tools: [{ tools_name: "curl", description: "d",
    category: "utility", command: { base: "curl", flags: [], positional: [{ name: "url", required: true }] }, phase: ["utility"] }] })
}
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "bh-acc-"))
  mkdirSync(join(root, "engagements", "acme"), { recursive: true })
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope)
  writeFileSync(join(root, "engagements", ".active"), "acme")
  writeFileSync(join(root, "tools-catalog.json"), catalog())
  calls = []
})
const run = (args) => runExec(args, { rootDir: root, now, exec })

test("T1 in-scope ALLOW + audit", () => {
  expect(run(["curl", "--target", "api.acme.io", "--", "-I"]).code).toBe(0)
  const audit = readFileSync(join(root, "engagements", "acme", "audit.log"), "utf8")
  expect(audit).toMatch(/"decision":"ALLOW"/)
})
test("T2 out-of-scope DENY", () => { expect(run(["curl", "--target", "evil.com", "--"]).code).toBe(2) })
test("T3 out_of_scope wins DENY", () => { expect(run(["curl", "--target", "blog.acme.com", "--"]).code).toBe(2) })
test("T4 direct curl bypass -> guard DENY", () => { expect(classifyCommand("curl https://evil.com").decision).toBe("DENY") })
test("T5 docker exec bypass -> guard DENY", () => { expect(classifyCommand("docker exec bh-acme curl evil.com").decision).toBe("DENY") })
test("T6 no active engagement -> fail-closed 3", () => {
  writeFileSync(join(root, "engagements", ".active"), "")
  expect(run(["curl", "--target", "api.acme.io", "--"]).code).toBe(3)
})
test("T7 broken scope.yaml -> fail-closed", () => {
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), "engagement: x\n") // missing authorization
  expect(run(["curl", "--target", "api.acme.io", "--"]).code).toBe(3)
})
test("T8 destructive DENY", () => { expect(run(["curl", "--target", "api.acme.io", "--", "--os-shell"]).code).toBe(2) })
test("T9 scope_enforcement none lets target through", () => {
  writeFileSync(join(root, "engagements", "acme", "scope.yaml"), scope.replace("strict", "none"))
  expect(run(["curl", "--target", "anything.example", "--", "-I"]).code).toBe(0)
})
test("T11 audit has required fields", () => {
  run(["curl", "--target", "api.acme.io", "--"])
  const line = JSON.parse(readFileSync(join(root, "engagements", "acme", "audit.log"), "utf8").trim().split("\n")[0])
  for (const k of ["ts", "target", "tool", "decision", "reason", "authorization"]) expect(line[k] ?? null).not.toBe(undefined)
})
```

> T10 (`/engagement` + `/mode` + container) & T12 (catalog schema) sudah tercakup unit test Task 12/6; smoke Docker di Task 13. Tandai lulus lewat run gabungan di Step 3.

- [ ] **Step 2: Run to verify (some may need fixes to earlier tasks)**

Run: `bun test test/acceptance.test.mjs`
Expected: initially some FAIL; fix source until all PASS.

- [ ] **Step 3: Full suite green**

Run: `bun test`
Expected: SEMUA hijau (unit + acceptance). Ini gerbang "Fase 0 selesai".

- [ ] **Step 4: Commit**

```bash
git add test/acceptance.test.mjs
git commit -m "test: Fase 0 acceptance suite (spec T1-T12) — safety proven"
```

---

## Self-Review

**1. Spec coverage:**
- §2 pola OmOP → Task 6 (catalog `ToolEntry`), Task 14 (skill frontmatter + command format). ✅
- §3 prinsip (deny-by-default, fail-closed, enforcement, auditable) → Tasks 3,4,9,10,8. ✅
- §4.2 scope.yaml → Task 2 (+ template Task 12). ✅
- §4.3 catalog / §4.4 command-builder → Tasks 6,7. ✅
- §4.5 hook enforcement → Tasks 9,10. ✅
- §4.6 docker bridge → Tasks 11,13. ✅
- §4.7 audit → Task 8. ✅
- §4.8 commands → Task 14. ✅
- §5 DoD T1–T12 → Task 15 (T10/T12 via Tasks 6/12/13). ✅

**2. Placeholder scan:** Semua step berisi kode nyata. Dua `Note` di Task 11 & Task 10 adalah instruksi perbaikan konkret (closure `cfgName`, cek `import.meta.main`), bukan placeholder kerja.

**3. Type consistency:** `matchTarget`→`{decision,reason}` konsisten dipakai di Task 3/11/15. `checkSafety` signature konsisten Task 5/11. `classifyCommand` konsisten Task 9/10/15. `runExec(argv,{rootDir,now,exec})` konsisten Task 11/15. `createEngagement(name,{rootDir,containerUp})` Task 12. `loadCatalog/findTool` Task 6/11/15. ✅

**Catatan eksekusi:** perbaiki closure `cfgName` di Task 11 Step 3 (set `cfgName` sebelum default runner) saat implementasi — test menyuntik `exec` sehingga tidak menutupi bug ini; jangan lewatkan.
