import type { ZoteroItem } from "@/types/zotero";

export interface ZoteroConfig {
	userId: string;
	apiKey: string;
	limit: number;
}

const FETCH_TIMEOUT_MS = 8000;

function hasZoteroConfig(config: ZoteroConfig) {
	return config.userId.trim() !== "" && config.apiKey.trim() !== "";
}

export async function fetchZoteroData(
	config: ZoteroConfig,
): Promise<ZoteroItem[]> {
	if (!hasZoteroConfig(config)) {
		return [];
	}

	try {
		const url = `https://api.zotero.org/users/${config.userId}/items/top?format=json&limit=${config.limit}`;
		const response = await fetch(url, {
			headers: {
				"Zotero-API-Key": config.apiKey,
				"Zotero-API-Version": "3",
			},
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
		});

		if (!response.ok) {
			console.warn(`[Zotero] fetch failed: ${response.status}`);
			return [];
		}

		const data = (await response.json()) as ZoteroItem[];
		const filteredData = data.filter(
			(item) =>
				item.data &&
				!["attachment", "annotation", "note"].includes(item.data.itemType),
		);
		return filteredData;
	} catch (error) {
		console.warn("[Zotero] fetch error:", error);
		return [];
	}
}
