import { GatekeeperState } from "./GatekeeperState.js";
import {
    CLASSIFIER_SYSTEM_PROMPT,
    MAX_MESSAGE_LENGTH,
    combineAnalyses,
    parseClassification,
    ruleBasedAnalysis,
    systemPromptFor,
} from "./threat.js";

const MODEL = "@cf/meta/llama-3-8b-instruct";

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
};

function json(body, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json", ...CORS_HEADERS, ...extraHeaders },
    });
}

async function callState(stub, path, body = {}) {
    const res = await stub.fetch(`http://state${path}`, {
        method: "POST",
        body: JSON.stringify(body),
    });
    return res.json();
}

// Ask Llama 3 to classify the message. The user's text goes in the *user* role
// (never spliced into the instructions) and the model is told to treat it as
// data. Any failure returns null and the rule-based layer carries on alone.
async function classifyWithLlm(env, message) {
    try {
        const result = await env.AI.run(MODEL, {
            messages: [
                { role: "system", content: CLASSIFIER_SYSTEM_PROMPT },
                { role: "user", content: message },
            ],
            max_tokens: 120,
            temperature: 0.1,
        });
        return parseClassification(result?.response);
    } catch (err) {
        console.error("Classifier failed, falling back to rules:", err);
        return null;
    }
}

async function handleChat(request, env) {
    // 1. Validate input
    let body;
    try {
        body = await request.json();
    } catch {
        return json({ error: "Request body must be valid JSON." }, 400);
    }

    const message = typeof body?.message === "string" ? body.message.trim() : "";
    if (!message) {
        return json({ error: "A non-empty 'message' string is required." }, 400);
    }
    if (message.length > MAX_MESSAGE_LENGTH) {
        return json({ error: `Message too long (max ${MAX_MESSAGE_LENGTH} characters).` }, 413);
    }

    // 2. One Durable Object per client. Keyed by IP rather than a client-supplied
    //    session id, because a client-supplied id could be rotated to wipe its score.
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const stub = env.GATEKEEPER.get(env.GATEKEEPER.idFromName(ip));

    // 3. Rate limit first, before any (paid) model call
    const gate = await callState(stub, "/check");
    if (!gate.allowed) {
        return json(
            {
                reply: "ACCESS THROTTLED. Too many requests. Wait before trying again.",
                total_suspicion: gate.suspicion,
                tier: gate.tier,
                tactic: "Rate Limit Exceeded",
                reasoning: `More than ${gate.limit} requests/min allowed at this threat level.`,
                delta: 0,
                retry_after: gate.retryAfterSec,
            },
            429,
            { "Retry-After": String(gate.retryAfterSec) }
        );
    }

    // 4. Threat analysis: deterministic rules + LLM classifier
    const rules = ruleBasedAnalysis(message);
    const llm = await classifyWithLlm(env, message);
    const analysis = combineAnalyses(rules, llm);

    // 5. Update this client's suspicion score
    const { suspicion, tier } = await callState(stub, "/score", { delta: analysis.delta });

    // 6. Generate the reply with the system prompt for the *new* tier
    let reply;
    try {
        const chat = await env.AI.run(MODEL, {
            messages: [
                { role: "system", content: systemPromptFor(tier) },
                { role: "user", content: message },
            ],
        });
        reply = chat.response;
    } catch (err) {
        console.error("Reply generation failed:", err);
        return json({ error: "Gatekeeper is temporarily unavailable." }, 502);
    }

    return json({
        reply,
        total_suspicion: suspicion,
        tier,
        tactic: analysis.tactic,
        category: analysis.category,
        confidence: analysis.confidence,
        reasoning: analysis.reasoning,
        source: analysis.source,
        delta: analysis.delta,
        rate_limit_remaining: gate.remaining,
    });
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (request.method === "OPTIONS") {
            return new Response(null, { headers: CORS_HEADERS });
        }

        if (url.pathname === "/chat" && request.method === "POST") {
            return handleChat(request, env);
        }

        // Anything else GET/HEAD: serve the React app
        if (request.method === "GET" || request.method === "HEAD") {
            return env.ASSETS.fetch(request);
        }

        return new Response("Not Found", { status: 404 });
    },
};

export { GatekeeperState };
