# 🐕 Boundhound

![tests](https://img.shields.io/badge/tests-1340%20passing-brightgreen)
![scope](https://img.shields.io/badge/scope-deny--by--default-red)
![runtime](https://img.shields.io/badge/Claude%20Code-plugin-blue)
![skills](https://img.shields.io/badge/skill%20library-81-8957e5)

> **An autonomous penetration-testing framework for Claude Code — with scope safety that's _enforced_, not requested.**

One command runs a whole engagement — **recon → enum → bounded exploit → verify → report** — while making it *technically impossible* for the agent to touch a target outside your authorized scope. Enforcement lives in a git-tracked hook and a CLI choke point the agent can't disable, so scope holds even if the model is jailbroken, confused, or wrong. Other "AI pentest" tools *ask* the agent to behave; Boundhound removes the choice.

## ✨ Highlights

- **🎯 One command** — `/fullscan` runs the full chain autonomously and hands you a submittable `report.md` (or drive each phase by hand).
- **🛡️ Enforced scope** — every tool call goes through one choke point (`bh-exec`) that refuses anything outside `scope.yaml`, before a packet leaves. A `PreToolUse` hook blocks any bypass.
- **🧨 Bounded exploitation** — sqlmap in proof-of-vulnerability mode; dump / OS-shell / file flags hard-denied by two layers.
- **♻️ Resilient** — `--resume` a killed scan, `--max-retries` transient failures (same bounded command), `--max-steps` ceiling. A DENY is never retried.
- **🔌 Burp-safe** — Burp runs host-side and bypasses the container, so a second deny-by-default guard scope-checks every Burp MCP call.
- **📚 81 technique playbooks** — a self-authored [`skills-library/`](skills-library/) across 11 categories, each wired to the tools + safety model.
- **🧾 Fully audited** — every run and every denial lands in a per-engagement `audit.log`.

## 🚀 Quick start

```bash
# install as a Claude Code plugin
/plugin marketplace add tuktukerz/boundhound
/plugin install boundhound@tuktukerz-marketplace

/engagement acme        # scaffold engagement, then fill in scope.yaml
/fullscan               # run the whole engagement → output/report/report.md
# non-intrusive pass:  /fullscan --no-exploit
```

## 📟 What a run looks like

```text
$ /fullscan --no-exploit
[recon]  subfinder → 14 subdomains · httpx → 6 live · nmap → open ports
[recon]  DENY blog.partner.io  (out of scope) — skipped + audited
[enum]   ffuf → /admin /.git/  · nuclei → 3 findings
[report] output/report/report.md   (2 medium · 4 info)
```

```markdown
# Penetration Test Report — acme
## Executive summary
| critical | high | medium | low | info |
|:-:|:-:|:-:|:-:|:-:|
|   0  |  0  |   2   |  0  |  4  |
### [MEDIUM] http-service — exposed .git/ at shop.acme.com
Remediation: block access to version-control metadata at the web server.
```

## 🧭 Capabilities

| Area | Tools / command | Bound |
|---|---|---|
| Recon | subfinder · httpx · nmap — `/recon` | deny-by-default scope; nmap non-aggressive |
| Enumeration | ffuf · nuclei — `/enum` | concurrency & rate caps |
| Exploitation | sqlmap — `/exploit` | proof-of-vuln only; weaponizing flags denied |
| Verification | `/verify` | re-runs the *same* bounded check, never escalates |
| Reporting | `/report` | pure renderer; never fabricates a finding |
| Orchestration | `/fullscan` | chains all phases; `--resume` / retry / budgets |
| Burp Suite | `/burp` · `bh-burp-scope` | separate deny-by-default MCP choke point |

Everything runs through the same enforced `bh-exec` choke point (or, for Burp, its own guard) — the framework can't do anything a manually-run, scope-checked command couldn't.

## 🛡️ How the safety works

```text
User / Agent
   │  direct call to a network tool?  ──► PreToolUse hook ──► DENY (bypass blocked)
   ▼
 bh-exec  ──►  scope check ──► out of scope?  ──► DENY + audit
   │           safety check ─► destructive/DoS? ─► DENY + audit
   ▼
 docker exec (bounded tool)  ──►  audit ALLOW
```

Enforcement is a **git-tracked hook + a CLI choke point** — a layer the agent doesn't control. Scope is deny-by-default and fail-closed: no active engagement, a broken `scope.yaml`, or an unresolvable target all refuse rather than run.

## 📚 Skill library

[`skills-library/`](skills-library/) holds **81 self-authored technique playbooks** across 11 categories (web-injection, access-control, auth/session, API, recon/OSINT, infra, info-disclosure, business-logic, client-side, methodology). Each names the bounded tool(s) and command(s) it uses; where a technique has no bounded tool yet, it says so and gives the safe in-scope path instead of inventing a capability. All are machine-validated (`test/skill-library.test.mjs`). These are source playbooks — the active per-phase skills under `.claude/skills/` are promoted deliberately.

Promote/demote a playbook with `bh-skill` (or `/skill`): `node bin/bh-skill.mjs list|promote <slug>|demote <slug>`. Promoting copies `skills-library/<slug>/` into `.claude/skills/<slug>/`; the 8 core pipeline skills can't be demoted.

## 🧪 Run from a clone (dev)

```bash
bun install
bun test                              # 1340 pass · 1 skip (docker smoke) · 0 fail
bin/bh-container up smoke              # start the tool container
node bin/bh-engagement.mjs acme       # scaffold an engagement → fill scope.yaml
node bin/bh-exec.mjs curl --target api.acme.io -- -I   # run a tool through the choke point
```

Dev mode keeps state in the checkout (`$CLAUDE_PROJECT_DIR`); installed as a plugin it uses `${CLAUDE_PLUGIN_DATA}`. Pass `--data-dir <path>` to override.

## 📁 Structure

```text
bin/        bh-exec (choke point) · per-phase CLIs · bh-fullscan · bh-burp-scope
hooks/      scope-guard.mjs (PreToolUse enforcement + Burp MCP guard)
src/        scope · safety · guard · audit · recon/enum/exploit/verify/report · orchestrate
.claude/    active skills + commands (/engagement /recon … /fullscan /burp)
skills-library/  81 technique playbooks (source)
docker/     lean multi-stage image (subfinder/httpx/nmap/ffuf/nuclei/sqlmap)
docs/       ARCHITECTURE.md + per-phase specs & plans
```

## ⚠️ Honest about the bounds

- **Exploitation is proof-of-vulnerability, not weaponization** — it confirms a flaw is real; it doesn't dump data, get a shell, or touch the filesystem.
- **Boundhound doesn't drive Burp on its own yet** — it enforces the safety layer around Burp MCP; the live drive-through needs your Burp Pro and is validated separately.
- **No mass / credential-flood / DoS** — the safety layer caps request rates and denies DoS-shaped activity.
- **One active engagement per install** (shared `.active`); running several concurrently isn't supported yet.

Built for authorized engagements, bug-bounty programs, and your own lab.

## 🧱 Design principles

1. **Safety before capability** — no offensive tool ships before the layer bounding it passes its tests.
2. **Enforcement, not instruction** — what must hold true is enforced by code/hooks, not asked of the agent.
3. **Authored, not imported** — every skill is written for Boundhound's own config and safety model.
4. **TDD + adversarial review** — each module is written test-first and reviewed by an independent pass before it lands.

---

The full phase-by-phase design story and roadmap live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Built iteratively with Claude Code — spec → plan → subagent-driven implementation, each step reviewed before moving on.
