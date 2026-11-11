import {
    BASELINE,
    BLOCKED_PENALTY,
    checkRateLimit,
    clamp,
    decay,
    tierFor,
} from "./threat.js";

const IDLE_CLEANUP_MS = 24 * 60 * 60 * 1000; // forget idle clients after a day

// One Durable Object per client. It owns that client's suspicion score and
// rate-limit window, so state is persistent and strictly serialised: two
// requests from the same client can never read-modify-write at the same time.
export class GatekeeperState {
    constructor(state) {
        this.state = state;
    }

    async load(now) {
        const stored = await this.state.storage.get(["suspicion", "updatedAt", "hits"]);
        const suspicion = stored.get("suspicion") ?? BASELINE; // ?? so a real 0 isn't treated as "unset"
        const updatedAt = stored.get("updatedAt") ?? now;
        const hits = stored.get("hits") ?? [];
        return { suspicion: decay(suspicion, now - updatedAt), hits };
    }

    async save(now, suspicion, hits) {
        await this.state.storage.put({ suspicion, updatedAt: now, hits });
        await this.state.storage.setAlarm(now + IDLE_CLEANUP_MS);
    }

    // Step 1 of a request: cool the score down, then apply the tier's rate limit.
    // Runs BEFORE any model call, so blocked clients cost us nothing.
    async check(now) {
        const { suspicion, hits } = await this.load(now);
        const tier = tierFor(suspicion);
        const rate = checkRateLimit(hits, now, tier);

        if (!rate.allowed) {
            const penalised = clamp(suspicion + BLOCKED_PENALTY);
            await this.save(now, penalised, rate.timestamps);
            return {
                allowed: false,
                suspicion: penalised,
                tier: tierFor(penalised),
                limit: rate.limit,
                remaining: 0,
                retryAfterSec: rate.retryAfterSec,
            };
        }

        await this.save(now, suspicion, rate.timestamps);
        return {
            allowed: true,
            suspicion,
            tier,
            limit: rate.limit,
            remaining: rate.remaining,
            retryAfterSec: 0,
        };
    }

    // Step 2: apply the delta from the threat analysis.
    async score(now, delta) {
        const { suspicion, hits } = await this.load(now);
        const updated = clamp(suspicion + delta);
        await this.save(now, updated, hits);
        return { suspicion: updated, tier: tierFor(updated) };
    }

    async fetch(request) {
        const url = new URL(request.url);
        const now = Date.now();

        if (request.method !== "POST") {
            return json({ error: "Method not allowed" }, 405);
        }

        if (url.pathname === "/check") {
            return json(await this.check(now));
        }

        if (url.pathname === "/score") {
            const { delta } = await request.json();
            if (typeof delta !== "number" || !Number.isFinite(delta)) {
                return json({ error: "delta must be a number" }, 400);
            }
            return json(await this.score(now, delta));
        }

        return json({ error: "Not found" }, 404);
    }

    async alarm() {
        await this.state.storage.deleteAll();
    }
}

function json(body, status = 200) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}
