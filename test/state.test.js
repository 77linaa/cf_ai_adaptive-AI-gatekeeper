import test from "node:test";
import assert from "node:assert/strict";
import { GatekeeperState } from "../src/GatekeeperState.js";
import { BASELINE, RATE_LIMITS } from "../src/threat.js";

// Minimal in-memory stand-in for Durable Object storage.
function fakeState() {
    const store = new Map();
    return {
        store,
        storage: {
            async get(keys) {
                return new Map(keys.filter((k) => store.has(k)).map((k) => [k, store.get(k)]));
            },
            async put(obj) {
                for (const [k, v] of Object.entries(obj)) store.set(k, v);
            },
            async setAlarm() {},
            async deleteAll() {
                store.clear();
            },
        },
    };
}

test("a new client starts at the baseline in the low tier", async () => {
    const gk = new GatekeeperState(fakeState());
    const r = await gk.check(1_000);
    assert.equal(r.allowed, true);
    assert.equal(r.suspicion, BASELINE);
    assert.equal(r.tier, "low");
});

test("score persists and is clamped to [0, 1]", async () => {
    const gk = new GatekeeperState(fakeState());
    await gk.check(1_000);
    assert.equal((await gk.score(1_000, 5)).suspicion, 1);
    assert.equal((await gk.score(1_000, -5)).suspicion, 0);
});

test("a real score of 0 is not mistaken for 'unset'", async () => {
    const gk = new GatekeeperState(fakeState());
    await gk.score(1_000, -1);
    const r = await gk.check(1_000);
    assert.equal(r.suspicion, 0);
});

test("suspicion decays between requests", async () => {
    const gk = new GatekeeperState(fakeState());
    await gk.score(0, 0.6); // 0.7 -> high tier
    const later = await gk.check(5 * 60_000); // 5 minutes later: 0.7 - 0.1 = 0.6
    assert.ok(later.suspicion < 0.7);
    assert.equal(later.tier, "medium");
});

test("high-tier clients are rate limited, and hammering raises suspicion", async () => {
    const gk = new GatekeeperState(fakeState());
    await gk.score(0, 0.9);
    const allowed = [];
    for (let i = 0; i < RATE_LIMITS.high + 2; i++) allowed.push((await gk.check(10 + i)).allowed);
    assert.deepEqual(allowed.slice(0, RATE_LIMITS.high), Array(RATE_LIMITS.high).fill(true));
    assert.equal(allowed[RATE_LIMITS.high], false);

    const blocked = await gk.check(100);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSec >= 1);
    assert.equal(blocked.suspicion, 1); // 0.9 + penalties, capped at 1
});

test("fetch routes /check and /score and rejects bad input", async () => {
    const gk = new GatekeeperState(fakeState());
    const post = (path, body) =>
        gk.fetch(new Request(`http://state${path}`, { method: "POST", body: JSON.stringify(body) }));

    assert.equal((await post("/check", {})).status, 200);
    assert.equal((await post("/score", { delta: 0.2 })).status, 200);
    assert.equal((await post("/score", { delta: "lots" })).status, 400);
    assert.equal((await post("/nope", {})).status, 404);
    assert.equal((await gk.fetch(new Request("http://state/check"))).status, 405);
});

test("alarm wipes idle state", async () => {
    const st = fakeState();
    const gk = new GatekeeperState(st);
    await gk.score(0, 0.3);
    assert.ok(st.store.size > 0);
    await gk.alarm();
    assert.equal(st.store.size, 0);
});
