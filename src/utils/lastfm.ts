import { profileConfig } from "@/config";
import type { LastfmRecentTracksResponse, LastfmTrack } from "@/types/lastfm";

const apiKey = process.env.LASTFM_API_KEY;
const username = process.env.LASTFM_USER || profileConfig.name;
const LASTFM_API_URL = "https://ws.audioscrobbler.com/2.0/";

function getLastfmEnv(): { apiKey: string; username: string } {
	if (!apiKey) {
		throw new Error("Missing LASTFM_API_KEY");
	}

	if (!username) {
		throw new Error("Missing LASTFM_USER");
	}

	return {
		apiKey,
		username,
	};
}

function isErrorResponse(
	payload: LastfmRecentTracksResponse,
): payload is LastfmRecentTracksResponse & { error: number; message?: string } {
	return typeof payload.error === "number";
}

function getTrackList(payload: LastfmRecentTracksResponse): LastfmTrack[] {
	const tracks = payload.recenttracks?.track;
	if (!tracks) {
		return [];
	}

	return Array.isArray(tracks) ? tracks : [tracks];
}

function getImageUrl(track: LastfmTrack): string | undefined {
	const images = track.image;
	if (!Array.isArray(images) || images.length === 0) {
		return undefined;
	}

	const preferredOrder = ["extralarge", "large", "medium", "small"];
	for (const size of preferredOrder) {
		const match = images.find(
			(image) => image.size === size && typeof image["#text"] === "string" && image["#text"],
		);
		if (match?.["#text"]) {
			return match["#text"];
		}
	}

	return images.find((image) => typeof image["#text"] === "string" && image["#text"])?.["#text"];
}

export interface LastfmNowPlaying {
	isPlaying: boolean;
	title: string;
	artist: string;
	album?: string;
	albumImageUrl?: string;
	songUrl?: string;
}

export async function getNowPlaying(): Promise<LastfmNowPlaying | null> {
	const env = getLastfmEnv();

	const params = new URLSearchParams({
		method: "user.getrecenttracks",
		user: env.username,
		api_key: env.apiKey,
		format: "json",
		limit: "1",
	});

	const response = await fetch(`${LASTFM_API_URL}?${params.toString()}`);
	const payload = (await response.json()) as LastfmRecentTracksResponse;

	if (!response.ok) {
		const message =
			typeof payload.message === "string" ? payload.message : "Unknown Last.fm error";
		throw new Error(`Last.fm recent tracks request failed (${response.status}): ${message}`);
	}

	if (isErrorResponse(payload)) {
		throw new Error(
			`Last.fm recent tracks request failed (${payload.error}): ${payload.message || "Unknown Last.fm error"}`,
		);
	}

	const [track] = getTrackList(payload);
	if (!track || track["@attr"]?.nowplaying !== "true") {
		return null;
	}

	const title = typeof track.name === "string" ? track.name.trim() : "";
	const artist =
		track.artist && typeof track.artist["#text"] === "string"
			? track.artist["#text"].trim()
			: "";

	if (!title || !artist) {
		return null;
	}

	const album =
		track.album && typeof track.album["#text"] === "string"
			? track.album["#text"].trim()
			: undefined;
	const songUrl = typeof track.url === "string" ? track.url : undefined;

	return {
		isPlaying: true,
		title,
		artist,
		album,
		albumImageUrl: getImageUrl(track),
		songUrl,
	};
}
