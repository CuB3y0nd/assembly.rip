import type { APIRoute } from "astro";

export const GET: APIRoute = async () => {
	const discordUserID = process.env.DISCORD_USER_ID;

	try {
		const response = await fetch(
			`https://api.lanyard.rest/v1/users/${discordUserID}`,
		);
		const data = await response.json();

		return new Response(JSON.stringify(data), {
			status: 200,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "public, s-maxage=30, stale-while-revalidate=30",
			},
		});
	} catch {
		return new Response(JSON.stringify({ success: false }), {
			status: 500,
		});
	}
};
