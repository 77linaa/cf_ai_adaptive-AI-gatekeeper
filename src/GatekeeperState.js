export class GatekeeperState {
    constructor(state) {
        this.state = state;
    }
    async fetch(request) {
        const url = new URL(request.url);

        let suspicion = (await this.state.storage.get("suspicion")) || 0.2;

        if (url.pathname === "/update" && request.method === "POST") {
            const data = await request.json();

            suspicion += data.delta;

            suspicion = Math.max(0, Math.min(suspicion, 1));

            await this.state.storage.put("suspicion", suspicion);
        }

        return new Response(
            JSON.stringify({ suspicion }),
            { headers: { "Content-Type": "application/json" } }
        );
    }
}