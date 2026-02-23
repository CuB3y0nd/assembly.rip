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

export async function fetchBangumiData(
	config: BangumiConfig,
	subjectType: number,
): Promise<UserSubjectCollection[]> {
	try {
		const { limit, delay, maxTotal } = config.pagination;
		let offset = 0;
		let allData: UserSubjectCollection[] = [];
		let hasMore = true;

		console.log(
			`[Bangumi] 开始获取用户 ${config.username} 的 subjectType ${subjectType} 数据...`,
		);

		while (hasMore) {
			if (maxTotal > 0 && allData.length >= maxTotal) {
				console.log(`[Bangumi] 已达到最大获取限制 ${maxTotal}，停止获取`);
				break;
			}

			const url = `${config.apiUrl}/v0/users/${config.username}/collections?subject_type=${subjectType}&limit=${limit}&offset=${offset}`;

			console.log(`[Bangumi] 正在获取数据: ${url} (已获取: ${allData.length})`);

			const response = await fetch(url, {
				headers: {
					"User-Agent": "CuB3y0nd/assembly.rip",
					Accept: "application/json",
				},
			});

			if (!response.ok) {
				console.warn(
					`[Bangumi] 无法获取数据 (状态码: ${response.status}):`,
					url,
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

		console.log(`[Bangumi] 总共获取到 ${allData.length} 条数据`);
		return allData;
	} catch (error) {
		console.error("[Bangumi] 获取数据时出错:", error);
		return [];
	}
}
