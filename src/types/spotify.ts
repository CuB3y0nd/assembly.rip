export interface SpotifyPlayerResponse {
	is_playing: boolean;
	item: {
		name: string;
		artists: { name: string }[];
		album: {
			name: string;
			images: { url: string }[];
		};
		external_urls: {
			spotify: string;
		};
		duration_ms: number;
	};
	progress_ms: number;
}
