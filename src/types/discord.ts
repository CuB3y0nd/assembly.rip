export type DiscordStatus = "online" | "idle" | "dnd" | "offline" | "loading";

export interface LanyardResponse {
	success: boolean;
	data: {
		discord_status: DiscordStatus;
		discord_user: {
			username: string;
			public_flags: number;
			id: string;
			discriminator: string;
			avatar: string;
		};
		activities: {
			type: number;
			state: string;
			name: string;
			id: string;
			details?: string;
			created_at: number;
			timestamps?: {
				start?: number;
				end?: number;
			};
			assets?: {
				large_text?: string;
				large_image?: string;
				small_text?: string;
				small_image?: string;
			};
		}[];
		listening_to_spotify: boolean;
		spotify?: {
			track_id: string;
			timestamps: {
				start: number;
				end: number;
			};
			song: string;
			artist: string;
			album_art_url: string;
			album: string;
		};
	};
}
