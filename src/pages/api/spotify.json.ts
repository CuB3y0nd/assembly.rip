export const prerender = false;

import type { APIRoute } from "astro";
import type { SpotifyPlayerResponse } from "../../types/spotify";
import { getNowPlaying } from "../../utils/spotify";

export const GET: APIRoute = async () => {
	const response = await getNowPlaying();

	if (response.status === 204 || response.status > 400) {
		return new Response(JSON.stringify({ isPlaying: false }), {
			headers: {
				"Cache-Control": "no-store",
			},
		});
	}

	const player = (await response.json()) as SpotifyPlayerResponse;

	return new Response(
		JSON.stringify({
			isPlaying: player.is_playing,
			title: player.item.name,
			artist: player.item.artists.map((a) => a.name).join(", "),
			album: player.item.album.name,
			albumImageUrl: player.item.album.images[0].url,
			songUrl: player.item.external_urls.spotify,
			duration: player.item.duration_ms,
			progress: player.progress_ms,
		}),
		{
			headers: {
				"Cache-Control": "no-store",
			},
		},
	);
};
