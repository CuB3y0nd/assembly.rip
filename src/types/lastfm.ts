export interface LastfmRecentTracksResponse {
	error?: number;
	message?: string;
	recenttracks?: {
		track?: LastfmTrack[] | LastfmTrack;
	};
}

export interface LastfmTrack {
	name?: string;
	url?: string;
	artist?: {
		"#text"?: string;
	};
	album?: {
		"#text"?: string;
	};
	image?: Array<{
		"#text"?: string;
		size?: string;
	}>;
	"@attr"?: {
		nowplaying?: string;
	};
}
