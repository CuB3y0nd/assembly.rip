import type { LanyardResponse } from "@/types/discord";

export async function fetchDiscordStatus(): Promise<LanyardResponse | null> {
	try {
		const resp = await fetch("/api/discord.json");
		if (!resp.ok) return null;
		return await resp.json();
	} catch (e) {
		console.error("Failed to fetch Discord status:", e);
		return null;
	}
}
