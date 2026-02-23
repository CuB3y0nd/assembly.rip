import type { ZoteroItem } from "@/types/zotero";

export interface ZoteroConfig {
	userId: string;
	apiKey: string;
	limit: number;
}

export async function fetchZoteroData(
	config: ZoteroConfig,
): Promise<ZoteroItem[]> {
	try {
		console.log("[Zotero] 开始获取数据...");
		const url = `https://api.zotero.org/users/${config.userId}/items?format=json&limit=${config.limit}&itemType=-attachment`;
		const response = await fetch(url, {
			headers: {
				"Zotero-API-Key": config.apiKey,
				"Zotero-API-Version": "3",
			},
		});

		if (!response.ok) {
			console.warn(`[Zotero] 无法获取数据 (状态码: ${response.status})`);
			return [];
		}

		const data = (await response.json()) as ZoteroItem[];
		console.log(`[Zotero] 总共获取到 ${data.length} 条数据`);
		return data;
	} catch (error) {
		console.error("[Zotero] 获取数据时出错:", error);
		return [];
	}
}
