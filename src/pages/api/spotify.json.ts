export const prerender = false;

import type { APIRoute } from "astro";
import type { SpotifyPlayerResponse } from "../../types/spotify";
import { getNowPlaying } from "../../utils/spotify";

export const GET: APIRoute = async () => {
	const response = await getNowPlaying();

	if (response.status === 204 || response.status > 400) {
		return new Response(
			JSON.stringify({
				isPlaying: false,
			}),
		);
	}

	const player = (await response.json()) as SpotifyPlayerResponse;
	const isPlaying = player.is_playing;
	const title = player.item.name;
	const artist = player.item.artists.map((_artist) => _artist.name).join(", ");
	const album = player.item.album.name;
	const albumImageUrl = player.item.album.images[0].url;
	const songUrl = player.item.external_urls.spotify;
	const duration = player.item.duration_ms;
	const progress = player.progress_ms;

	return new Response(
		JSON.stringify({
			isPlaying,
			title,
			artist,
			album,
			albumImageUrl,
			songUrl,
			duration,
			progress,
		}),
	);
};
