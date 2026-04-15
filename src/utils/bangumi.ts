import type {
	UserSubjectCollection,
	UserSubjectCollectionResponse,
} from "@/types/bangumi";

export interface BangumiConfig {
	username: string;
	apiUrl: string;
	pagination: {
		limit: number;
		delay: number;
		maxTotal: number;
	};
}

const FETCH_TIMEOUT_MS = 8000;

function hasBangumiConfig(config: BangumiConfig) {
	return config.username.trim() !== "" && config.apiUrl.trim() !== "";
}

export async function fetchBangumiData(
	config: BangumiConfig,
	subjectType: number,
): Promise<UserSubjectCollection[]> {
	if (!hasBangumiConfig(config)) {
		return [];
	}

	try {
		const { limit, delay, maxTotal } = config.pagination;
		let offset = 0;
		let allData: UserSubjectCollection[] = [];
		let hasMore = true;

		while (hasMore) {
			if (maxTotal > 0 && allData.length >= maxTotal) {
				break;
			}

			const url = `${config.apiUrl}/v0/users/${config.username}/collections?subject_type=${subjectType}&limit=${limit}&offset=${offset}`;

			const response = await fetch(url, {
				headers: {
					"User-Agent": "CuB3y0nd/assembly.rip",
					Accept: "application/json",
				},
				signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			});

			if (!response.ok) {
				console.warn(
					`[Bangumi] ${subjectType} fetch failed: ${response.status}`,
				);
				break;
			}

			const data = (await response.json()) as UserSubjectCollectionResponse;
			const currentBatch = data.data || [];

			if (currentBatch.length > 0) {
				allData = allData.concat(currentBatch);
				offset += limit;

				if (currentBatch.length < limit) {
					hasMore = false;
				}
			} else {
				hasMore = false;
			}

			if (hasMore) {
				await new Promise((resolve) => setTimeout(resolve, delay));
			}
		}

		return allData;
	} catch (error) {
		console.warn(`[Bangumi] ${subjectType} fetch error:`, error);
		return [];
	}
}
