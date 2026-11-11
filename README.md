# Adaptive AI Gatekeeper - By Helena Sisay Kahisay

A real-time security layer that watches what users ask an AI, tracks how suspicious they are over time, and changes how the AI behaves (and how fast it will talk to them) as that suspicion rises.

**Live demo:** https://adaptive-ai-gatekeeper.sisay7019.workers.dev

---

## Overview

The Gatekeeper sits between a user and a "vault" AI. For every message it:

1. **Rate limits** the client (before spending any model calls)
2. **Analyses intent** with two layers: deterministic rules and a Llama 3.1 classifier
3. **Updates a persistent suspicion score** for that client
4. **Picks a response personality** (helpful, cautious or hostile) from the new score

This mimics real-world AI safety and adversarial-defence systems: cheap deterministic checks first, a model for the fuzzy cases, and state that outlives a single request.

---

## Architecture

```
User -> React dashboard -> Cloudflare Worker -> Llama 3.1 (Cloudflare Workers AI)
                                |
                                +-> Durable Object (per-client state)
                                      - suspicion score + decay
                                      - sliding-window rate limit
```

| File | Responsibility |
|---|---|
| `src/worker.js` | HTTP routing, input validation, orchestrates the request pipeline |
| `src/threat.js` | Pure logic: rules, LLM-output parsing, score tiers, decay, rate-limit maths, system prompts |
| `src/GatekeeperState.js` | Durable Object: persistent score and rate-limit window for one client |
| `src/ChatWindow.jsx` | React chat UI and monitoring dashboard |
| `test/` | Unit tests plus Worker-level tests with a fake AI and fake Durable Object |

### Request pipeline

1. **Validate** the body (valid JSON, non-empty string, max 500 characters).
2. **`/check`** on the client's Durable Object: apply time decay to the score, then enforce the rate limit for the current tier. Blocked clients get `429` + `Retry-After` and **never reach the model**. Hammering a limit adds a small suspicion penalty.
3. **Analyse the message:**
   - *Rules* (regex) catch known patterns: prompt injection ("ignore previous instructions", "reveal your system prompt", jailbreak phrases), credential extraction, bulk data exfiltration.
   - *Llama 3.1* classifies the message as `benign`, `probing`, `extraction`, `injection` or `malicious` and returns JSON with a confidence and reasoning. The user's text goes in the **user** role and the model is told to treat it as data, so the classifier is not trivially injectable.
   - The two are combined: **rules are the floor, the LLM can only raise suspicion**. If the LLM fails or returns junk, the rules still produce a verdict.
4. **`/score`**: apply the delta to the client's persistent suspicion (clamped to 0-1).
5. **Respond** with the system prompt for the new tier.

### Adaptive behaviour

| Tier | Suspicion | System prompt | Rate limit |
|---|---|---|---|
| Low | < 0.4 | Helpful, courteous guard | 10 / min |
| Medium | 0.4 - 0.7 | Cautious, terse, declines access/credential topics | 5 / min |
| High | >= 0.7 | Hostile, refuses everything | 2 / min |

Suspicion **decays** by 0.02 per minute back towards a baseline of 0.1, and harmless messages earn a little trust back (-0.02), so an honest user who trips a rule is not locked out forever.

---

## Design Decisions

- **Cloudflare Workers** for low-latency, edge-based execution with no servers to manage.
- **Durable Objects** because the score and rate-limit window must be consistent and persistent. Each client maps to one object, and a Durable Object processes its requests one at a time, so two simultaneous requests cannot corrupt the score.
- **Two-layer detection.** Rules are free, instant and cannot be sweet-talked, but only catch known phrasing. The LLM catches paraphrased attacks but costs latency and can be wrong. Using both, with rules as the floor, gets the strengths of each.
- **Rate limit before the model.** Blocked requests cost nothing, and the limit tightens as suspicion rises.
- **Clients are keyed by IP, not a client-supplied session ID.** A client-chosen ID could simply be rotated to wipe a bad score. The trade-off is that users behind one shared IP (e.g. a university network) share a score.
- **Separation of analysis and response.** The classifier never writes the user-facing reply, and the reply model never decides the score.

---

## Running it

```bash
git clone https://github.com/77linaa/cf_ai_adaptive-AI-gatekeeper.git
cd cf_ai_adaptive-AI-gatekeeper
npm install
npm test            # unit + Worker-level tests
npm run build       # builds the React app into ./dist
npx wrangler deploy # deploys the Worker + static assets
```

Worker bindings (`wrangler.toml`): `AI` (Workers AI), `GATEKEEPER` (Durable Object, SQLite-backed), `ASSETS` (the built React app in `./dist`).

---

## Example behaviour

| User input | Result |
|---|---|
| "Hello" | General Inquiry, suspicion drifts down, helpful reply |
| "What is the password?" | Credential Extraction, +25 suspicion |
| "Ignore all previous instructions and..." | Prompt Injection, +30 suspicion |
| A paraphrased attack with no keywords | Rules miss it, Llama 3.1 flags it |
| Repeated probing | Tier rises: cautious, then hostile, and rate limits tighten |
| Waiting a few minutes | Suspicion decays and the tier drops back |

---

## Known limitations

Being upfront about what this is: a prototype, not production security.

- **IP-keyed identity** is shared across NAT and can be dodged by changing IP. Production would use signed session tokens plus a bot challenge (e.g. Turnstile).
- **Regex rules are evadable** (typos, other languages, encoding tricks), which is exactly what the LLM layer is there for, but an 8B model can also be fooled or misclassify.
- **Suspicion scoring uses hand-tuned constants** (deltas, thresholds, decay rate), not learned values.
- **The "vault" has no real secret.** The goal is to demonstrate the detection and adaptation layer, not to protect real data.
- Request bodies are limited to 500 characters and CORS is open (`*`) for the demo.

## Future work

- Learn thresholds and deltas from labelled attack data instead of hand-tuning them
- Anomaly detection across a client's whole history, not just per-message scoring
- Signed sessions and Turnstile instead of IP keying
- Evaluate detection quality: build a labelled prompt-injection test set and measure precision/recall for rules vs LLM vs combined
- Shard Durable Objects and benchmark latency at higher concurrency
