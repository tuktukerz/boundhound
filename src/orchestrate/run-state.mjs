// src/orchestrate/run-state.mjs
//
// Phase 7 resilience (spec §2): a PURE, deterministic run-state model that
// lets bh-fullscan resume an interrupted scan. No I/O here on purpose -- the
// CLI (bin/bh-fullscan.mjs) owns reading/writing the state file at
// engagements/<active>/output/fullscan-state.json; these functions only
// ever see a plain {version, done} object in and a plain object/string out,
// so they unit-test against literals with no filesystem involved. Like
// findings.mjs, every function here tolerates missing/garbage input rather
// than throwing -- a corrupt or half-written state file must never abort a
// scan, it must just resume as "nothing done yet". And per spec §2, nothing
// here may call Date.now()/Math.random()/new Date(): a step's identity and
// a state's shape must be a pure function of their inputs alone, forever.

const VERSION = 1

// The identifying tuple for one planned unit of work (one stage running one
// tool against one target). Joined with "|" into a flat string key -- a
// plain object can't be a Map/Set key or a JSON object key without this.
// String()-coerce each field (matching findings.mjs's makeId) so a garbage
// or missing field (undefined, null, a number) still hashes predictably
// instead of producing "undefined" via implicit template-literal coercion
// surprises for some fields and not others.
export function stepKey({ stage, tool, target } = {}) {
  return `${String(stage)}|${String(tool)}|${String(target)}`
}

// The state resume tracks: a schema version (so a future format change can
// detect and discard an incompatible file -- not yet exercised, but the
// seam is here) plus a flat map of stepKey -> true for every completed
// unit. `done` is a plain object, not a Set/Map, so it serializes to JSON
// with no extra work.
export function emptyState() {
  return { version: VERSION, done: {} }
}

// False for a missing key AND for a malformed/garbage state -- a corrupt
// state object must resume as "nothing done yet", never throw and abort
// the scan it's meant to make resumable.
export function isDone(state, key) {
  const done = state?.done
  if (!done || typeof done !== "object" || Array.isArray(done)) return false
  return done[key] === true
}

// Returns a NEW state with `key` recorded done -- never mutates `state`
// (its own `done` map included), so a caller may keep and later compare a
// reference to the prior state. A missing/garbage input state is treated as
// emptyState() rather than throwing or propagating the garbage into the
// result.
export function markDone(state, key) {
  const base = state && typeof state === "object" && !Array.isArray(state) ? state : emptyState()
  const version = typeof base.version === "number" ? base.version : VERSION
  const done = base.done && typeof base.done === "object" && !Array.isArray(base.done) ? base.done : {}
  return { version, done: { ...done, [key]: true } }
}

// Tolerant JSON -> state. Anything that isn't exactly {version, done:{...}}
// shaped -- empty string, truncated/invalid JSON, "null", an array, a
// wrong-shape object -- falls back to emptyState() rather than throwing.
// Only `done` entries whose value is literally `true` survive, so a
// hand-edited or partially-written file can't inject non-boolean garbage
// into the state isDone/markDone rely on.
export function parseState(text) {
  if (typeof text !== "string" || text.length === 0) return emptyState()

  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    return emptyState()
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return emptyState()

  const rawDone = parsed.done
  if (!rawDone || typeof rawDone !== "object" || Array.isArray(rawDone)) return emptyState()

  const done = {}
  for (const [key, value] of Object.entries(rawDone)) {
    if (value === true) done[key] = true
  }

  const version = typeof parsed.version === "number" ? parsed.version : VERSION
  return { version, done }
}

// state -> JSON. Rebuilds a clean {version, done} shape from whatever
// version/done fields the input carries (mirroring parseState's tolerance)
// rather than JSON.stringify-ing the input verbatim, so serializeState is
// safe to call on a garbage/partial state too and still round-trips through
// parseState to an equivalent value.
export function serializeState(state) {
  const base = state && typeof state === "object" && !Array.isArray(state) ? state : emptyState()
  const version = typeof base.version === "number" ? base.version : VERSION
  const rawDone = base.done && typeof base.done === "object" && !Array.isArray(base.done) ? base.done : {}

  const done = {}
  for (const [key, value] of Object.entries(rawDone)) {
    if (value === true) done[key] = true
  }

  return JSON.stringify({ version, done })
}
