// src/orchestrate/run-state.test.mjs
import { test, expect } from "bun:test"
import { stepKey, emptyState, isDone, markDone, parseState, serializeState } from "./run-state.mjs"

// --- S1: stepKey (pure, deterministic) --------------------------------------

test("stepKey: same tuple -> identical key every call (stable across calls)", () => {
  const tuple = { stage: "recon:httpx", tool: "httpx", target: "http://acme.io" }
  const a = stepKey(tuple)
  const b = stepKey(tuple)
  const c = stepKey({ ...tuple })
  expect(a).toBe(b)
  expect(a).toBe(c)
  expect(typeof a).toBe("string")
})

test("stepKey: distinct tuples -> distinct keys", () => {
  const base = { stage: "recon:httpx", tool: "httpx", target: "http://acme.io" }
  const diffStage = stepKey({ ...base, stage: "recon:nmap" })
  const diffTool = stepKey({ ...base, tool: "nmap" })
  const diffTarget = stepKey({ ...base, target: "http://api.acme.io" })
  const original = stepKey(base)

  const keys = [original, diffStage, diffTool, diffTarget]
  expect(new Set(keys).size).toBe(keys.length)
})

test("stepKey: never throws on missing/garbage input", () => {
  expect(() => stepKey({})).not.toThrow()
  expect(() => stepKey(undefined)).not.toThrow()
  expect(() => stepKey({ stage: null, tool: undefined, target: 42 })).not.toThrow()
  expect(typeof stepKey(undefined)).toBe("string")
})

// Regression: a naive `${stage}|${tool}|${target}` join lets a field's own
// contents forge a collision with a DIFFERENT tuple -- this must never
// happen, since stepKey becomes the resume dedup key (Task 2) and a
// collision there would make `--resume` silently skip a step that never
// ran. Fails against the old unescaped join, passes against the current
// JSON.stringify(["stage","tool","target"]) encoding.
test("stepKey: collision-proof against delimiter/quote/bracket characters inside a field", () => {
  const pairs = [
    // stage:"a|b",tool:"c" vs stage:"a",tool:"b|c" -- both naively join to "a|b|c|d"
    [
      { stage: "a|b", tool: "c", target: "d" },
      { stage: "a", tool: "b|c", target: "d" },
    ],
    // pipe inside target
    [
      { stage: "recon:httpx", tool: "httpx", target: "http://a|b" },
      { stage: "recon:httpx", tool: "httpx|extra", target: "b" },
    ],
    // double-quote inside a field
    [
      { stage: 'a"b', tool: "c", target: "d" },
      { stage: "a", tool: '"b', target: 'c"d' },
    ],
    // bracket characters inside a field (adversarial against a naive
    // JSON-ish encoding too, not just "|")
    [
      { stage: "a]", tool: "[b", target: "c" },
      { stage: "a", tool: "]", target: "[b,c]" },
    ],
  ]

  for (const [a, b] of pairs) {
    expect(stepKey(a)).not.toBe(stepKey(b))
  }
})

test("stepKey: same tuple is still stable under the new key format", () => {
  const tuple = { stage: "a|b", tool: "c", target: "http://a|b\"c]" }
  expect(stepKey(tuple)).toBe(stepKey({ ...tuple }))
  expect(stepKey(tuple)).toBe(stepKey(tuple))
})

// --- emptyState --------------------------------------------------------------

test("emptyState: {version, done:{}} shape, version is a small constant integer", () => {
  const state = emptyState()
  expect(typeof state.version).toBe("number")
  expect(Number.isInteger(state.version)).toBe(true)
  expect(state.done).toEqual({})
})

test("emptyState: two calls produce equal but independent objects", () => {
  const a = emptyState()
  const b = emptyState()
  expect(a).toEqual(b)
  a.done.x = true
  expect(b.done).toEqual({})
})

// --- isDone / markDone ---------------------------------------------------

test("isDone: false on emptyState() for any key", () => {
  expect(isDone(emptyState(), "any|key|here")).toBe(false)
})

test("isDone: false for a missing key in a non-empty state", () => {
  const state = markDone(emptyState(), "recon:httpx|httpx|http://acme.io")
  expect(isDone(state, "recon:nmap|nmap|acme.io")).toBe(false)
})

test("markDone -> isDone: recorded key reads back true", () => {
  const key = stepKey({ stage: "recon:httpx", tool: "httpx", target: "http://acme.io" })
  const state = markDone(emptyState(), key)
  expect(isDone(state, key)).toBe(true)
})

test("markDone: does NOT mutate the input state (pure)", () => {
  const original = emptyState()
  const snapshotBefore = JSON.parse(JSON.stringify(original))
  const updated = markDone(original, "some|step|key")

  expect(original).toEqual(snapshotBefore)
  expect(original.done).toEqual({})
  expect(updated).not.toBe(original)
  expect(updated.done).not.toBe(original.done)
  expect(isDone(updated, "some|step|key")).toBe(true)
  expect(isDone(original, "some|step|key")).toBe(false)
})

test("markDone: accumulates multiple keys without losing earlier ones", () => {
  let state = emptyState()
  state = markDone(state, "a|b|c")
  state = markDone(state, "d|e|f")
  expect(isDone(state, "a|b|c")).toBe(true)
  expect(isDone(state, "d|e|f")).toBe(true)
  expect(isDone(state, "g|h|i")).toBe(false)
})

test("markDone: garbage/missing input state treated as emptyState(), never throws", () => {
  expect(() => markDone(undefined, "k")).not.toThrow()
  expect(() => markDone(null, "k")).not.toThrow()
  expect(() => markDone("garbage", "k")).not.toThrow()
  expect(() => markDone([1, 2, 3], "k")).not.toThrow()
  expect(isDone(markDone(undefined, "k"), "k")).toBe(true)
  expect(isDone(markDone({ done: "not-an-object" }, "k"), "k")).toBe(true)
})

test("isDone: never throws on malformed/garbage state", () => {
  expect(() => isDone(undefined, "k")).not.toThrow()
  expect(() => isDone(null, "k")).not.toThrow()
  expect(() => isDone("garbage", "k")).not.toThrow()
  expect(() => isDone(42, "k")).not.toThrow()
  expect(() => isDone({}, "k")).not.toThrow()
  expect(() => isDone({ done: null }, "k")).not.toThrow()
  expect(() => isDone({ done: [1, 2] }, "k")).not.toThrow()
  expect(() => isDone({ done: "nope" }, undefined)).not.toThrow()

  expect(isDone(undefined, "k")).toBe(false)
  expect(isDone(null, "k")).toBe(false)
  expect(isDone("garbage", "k")).toBe(false)
  expect(isDone(42, "k")).toBe(false)
  expect(isDone({}, "k")).toBe(false)
  expect(isDone({ done: null }, "k")).toBe(false)
  expect(isDone({ done: [1, 2] }, "k")).toBe(false)
})

// --- parseState (tolerant, never throws) ------------------------------------

test("parseState: empty string -> emptyState()", () => {
  expect(parseState("")).toEqual(emptyState())
})

test("parseState: truncated/invalid JSON -> emptyState()", () => {
  expect(parseState("{")).toEqual(emptyState())
})

test("parseState: literal 'null' -> emptyState()", () => {
  expect(parseState("null")).toEqual(emptyState())
})

test("parseState: literal '[]' (array, wrong shape) -> emptyState()", () => {
  expect(parseState("[]")).toEqual(emptyState())
})

test("parseState: valid JSON but wrong-shape object -> emptyState()", () => {
  expect(parseState('{"foo":"bar"}')).toEqual(emptyState())
  expect(parseState('{"version":1}')).toEqual(emptyState())
  expect(parseState('{"done":"not-an-object"}')).toEqual(emptyState())
  expect(parseState('{"done":[1,2,3]}')).toEqual(emptyState())
})

test("parseState: non-JSON garbage strings never throw and fall back to emptyState()", () => {
  const garbageInputs = ["", "{", "null", "[]", "not json at all", "undefined", "{,}", "12345", "true"]
  for (const input of garbageInputs) {
    expect(() => parseState(input)).not.toThrow()
    expect(parseState(input)).toEqual(emptyState())
  }
})

test("parseState: never throws on non-string input", () => {
  expect(() => parseState(undefined)).not.toThrow()
  expect(() => parseState(null)).not.toThrow()
  expect(() => parseState(42)).not.toThrow()
  expect(() => parseState({})).not.toThrow()
  expect(parseState(undefined)).toEqual(emptyState())
  expect(parseState(null)).toEqual(emptyState())
  expect(parseState(42)).toEqual(emptyState())
  expect(parseState({})).toEqual(emptyState())
})

test("parseState: valid well-formed state parses correctly", () => {
  const text = JSON.stringify({ version: 1, done: { "a|b|c": true } })
  expect(parseState(text)).toEqual({ version: 1, done: { "a|b|c": true } })
})

test("parseState: non-true done values are dropped", () => {
  const text = JSON.stringify({ version: 1, done: { "a|b|c": true, "d|e|f": false, "g|h|i": "yes" } })
  expect(parseState(text)).toEqual({ version: 1, done: { "a|b|c": true } })
})

// --- serializeState / round-trip --------------------------------------------

test("serializeState: returns a JSON string", () => {
  const text = serializeState(emptyState())
  expect(typeof text).toBe("string")
  expect(() => JSON.parse(text)).not.toThrow()
})

test("serializeState -> parseState round-trips to an equivalent empty state", () => {
  const state = emptyState()
  expect(parseState(serializeState(state))).toEqual(state)
})

test("serializeState -> parseState round-trips a state with recorded steps", () => {
  let state = emptyState()
  state = markDone(state, stepKey({ stage: "recon:httpx", tool: "httpx", target: "http://acme.io" }))
  state = markDone(state, stepKey({ stage: "enum:nuclei", tool: "nuclei", target: "http://acme.io" }))

  const roundTripped = parseState(serializeState(state))
  expect(roundTripped).toEqual(state)
  expect(isDone(roundTripped, stepKey({ stage: "recon:httpx", tool: "httpx", target: "http://acme.io" }))).toBe(true)
  expect(isDone(roundTripped, stepKey({ stage: "enum:nuclei", tool: "nuclei", target: "http://acme.io" }))).toBe(true)
})

test("serializeState: never throws on garbage input", () => {
  expect(() => serializeState(undefined)).not.toThrow()
  expect(() => serializeState(null)).not.toThrow()
  expect(() => serializeState("garbage")).not.toThrow()
  expect(() => serializeState([1, 2, 3])).not.toThrow()
  expect(parseState(serializeState(undefined))).toEqual(emptyState())
})
