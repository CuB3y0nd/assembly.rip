export const prerender = false;

import type { APIRoute } from "astro";
import { getNowPlaying } from "../../utils/lastfm";

export const GET: APIRoute = async () => {
	try {
		const track = await getNowPlaying();
		if (!track) {
			return new Response(
				JSON.stringify({
					isPlaying: false,
				}),
			);
		}

		return new Response(JSON.stringify(track));
	} catch (error) {
		console.error("[Last.fm]", error);
		return new Response(
			JSON.stringify({
				isPlaying: false,
				error: "lastfm_unavailable",
			}),
			{ status: 502 },
		);
	}
};
