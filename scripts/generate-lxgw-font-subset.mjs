import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const sourceRoot = path.join(repoRoot, "src");
const fontRoot = path.join(
	repoRoot,
	"node_modules",
	"@chinese-fonts",
	"lxgwwenkaibright",
	"dist",
	"LXGWBright-Light",
);
const sourceCssPath = path.join(fontRoot, "result.css");
const outputCssPath = path.join(
	repoRoot,
	"src",
	"styles",
	"lxgw-bright-light-subset.css",
);
const fetchTimeoutMs = 8000;

const textExtensions = new Set([
	".astro",
	".cjs",
	".css",
	".js",
	".json",
	".md",
	".mdx",
	".mjs",
	".svelte",
	".styl",
	".ts",
	".tsx",
	".txt",
	".yml",
	".yaml",
]);

async function walkTextFiles(dir) {
	const entries = await fs.readdir(dir, { withFileTypes: true });
	const files = [];

	for (const entry of entries) {
		if (entry.name === "node_modules" || entry.name === ".git") {
			continue;
		}

		const fullPath = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			files.push(...(await walkTextFiles(fullPath)));
			continue;
		}

		if (textExtensions.has(path.extname(entry.name))) {
			files.push(fullPath);
		}
	}

	return files;
}

async function loadEnvFile(filePath) {
	try {
		const content = await fs.readFile(filePath, "utf8");
		for (const rawLine of content.split(/\r?\n/)) {
			const line = rawLine.trim();
			if (!line || line.startsWith("#")) {
				continue;
			}

			const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
			if (!match) {
				continue;
			}

			const [, key, rawValue] = match;
			if (process.env[key] !== undefined) {
				continue;
			}

			let value = rawValue.trim();
			if (
				(value.startsWith('"') && value.endsWith('"')) ||
				(value.startsWith("'") && value.endsWith("'"))
			) {
				value = value.slice(1, -1);
			}
			process.env[key] = value;
		}
	} catch (error) {
		if (error?.code !== "ENOENT") {
			console.warn(`[font:subset] Failed to read ${path.basename(filePath)}:`, error);
		}
	}
}

function collectCodePoints(text) {
	const points = new Set();
	for (const char of text) {
		const point = char.codePointAt(0);
		if (point === undefined) {
			continue;
		}
		if (point < 0x20 && point !== 0x09 && point !== 0x0a && point !== 0x0d) {
			continue;
		}
		points.add(point);
	}
	return points;
}

function lowerBound(values, target) {
	let low = 0;
	let high = values.length;
	while (low < high) {
		const mid = low + ((high - low) >> 1);
		if (values[mid] < target) {
			low = mid + 1;
		} else {
			high = mid;
		}
	}
	return low;
}

function parseUnicodeToken(token) {
	const normalized = token.trim().toUpperCase();
	if (!normalized.startsWith("U+")) {
		return null;
	}

	const body = normalized.slice(2);
	if (body.includes("-")) {
		const [start, end] = body.split("-");
		return [Number.parseInt(start, 16), Number.parseInt(end, 16)];
	}

	if (body.includes("?")) {
		return [
			Number.parseInt(body.replaceAll("?", "0"), 16),
			Number.parseInt(body.replaceAll("?", "F"), 16),
		];
	}

	const value = Number.parseInt(body, 16);
	return [value, value];
}

function rangeMatches(rangeList, usedCodePoints) {
	for (const token of rangeList.split(",")) {
		const range = parseUnicodeToken(token);
		if (!range) {
			continue;
		}
		const [start, end] = range;
		const index = lowerBound(usedCodePoints, start);
		if (index < usedCodePoints.length && usedCodePoints[index] <= end) {
			return true;
		}
	}

	return false;
}

function addTextToCodePoints(target, text) {
	if (!text) {
		return;
	}

	for (const point of collectCodePoints(String(text))) {
		target.add(point);
	}
}

async function fetchJson(url, init) {
	const response = await fetch(url, {
		...init,
		signal: AbortSignal.timeout(fetchTimeoutMs),
	});

	if (!response.ok) {
		throw new Error(`${response.status} ${response.statusText}`);
	}

	return response.json();
}

async function collectBangumiCodePoints(target) {
	const username = process.env.BANGUMI_USERNAME?.trim();
	if (!username) {
		return;
	}

	const subjectTypes = [2, 4, 6];
	for (const subjectType of subjectTypes) {
		let offset = 0;
		let hasMore = true;

		while (hasMore && offset < 1000) {
			try {
				const payload = await fetchJson(
					`https://api.bgm.tv/v0/users/${username}/collections?subject_type=${subjectType}&limit=50&offset=${offset}`,
					{
						headers: {
							"User-Agent": "CuB3y0nd/assembly.rip",
							Accept: "application/json",
						},
					},
				);

				const items = Array.isArray(payload?.data) ? payload.data : [];
				for (const item of items) {
					addTextToCodePoints(target, item.comment);
					addTextToCodePoints(target, item.subject?.name);
					addTextToCodePoints(target, item.subject?.name_cn);
					addTextToCodePoints(target, item.subject?.short_summary);
					for (const tag of item.subject?.tags ?? []) {
						addTextToCodePoints(target, tag.name);
					}
				}

				hasMore = items.length === 50;
				offset += 50;
			} catch (error) {
				console.warn(`[font:subset] Bangumi ${subjectType} skipped:`, error);
				hasMore = false;
			}
		}
	}
}

async function collectZoteroCodePoints(target) {
	const userId = process.env.ZOTERO_USER_ID?.trim();
	const apiKey = process.env.ZOTERO_KEY?.trim();
	if (!userId || !apiKey) {
		return;
	}

	try {
		const items = await fetchJson(
			`https://api.zotero.org/users/${userId}/items/top?format=json&limit=100`,
			{
				headers: {
					"Zotero-API-Key": apiKey,
					"Zotero-API-Version": "3",
				},
			},
		);

		for (const item of Array.isArray(items) ? items : []) {
			const data = item?.data;
			if (!data || ["attachment", "annotation", "note"].includes(data.itemType)) {
				continue;
			}

			addTextToCodePoints(target, data.title);
			addTextToCodePoints(target, data.abstractNote);
			addTextToCodePoints(target, data.publisher);
			addTextToCodePoints(target, data.publicationTitle);
			addTextToCodePoints(target, item?.meta?.creatorSummary);
			for (const creator of data.creators ?? []) {
				addTextToCodePoints(target, creator.firstName);
				addTextToCodePoints(target, creator.lastName);
				addTextToCodePoints(target, creator.name);
			}
			for (const tag of data.tags ?? []) {
				addTextToCodePoints(target, tag.tag);
			}
		}
	} catch (error) {
		console.warn("[font:subset] Zotero skipped:", error);
	}
}

async function main() {
	await loadEnvFile(path.join(repoRoot, ".env"));
	await loadEnvFile(path.join(repoRoot, ".env.local"));

	const textFiles = await walkTextFiles(sourceRoot);
	const rootFiles = [
		path.join(repoRoot, "astro.config.mjs"),
		path.join(repoRoot, "tailwind.config.cjs"),
	];

	const usedCodePoints = new Set();
	for (const filePath of [...textFiles, ...rootFiles]) {
		const content = await fs.readFile(filePath, "utf8");
		for (const point of collectCodePoints(content)) {
			usedCodePoints.add(point);
		}
	}

	await Promise.all([
		collectBangumiCodePoints(usedCodePoints),
		collectZoteroCodePoints(usedCodePoints),
	]);

	const sortedPoints = [...usedCodePoints].sort((a, b) => a - b);
	const sourceCss = await fs.readFile(sourceCssPath, "utf8");
	const blocks = sourceCss.match(/@font-face\{[^}]+\}/g) ?? [];
	const keptBlocks = [];

	for (const block of blocks) {
		const rangeMatch = block.match(/unicode-range:([^;]+);/);
		if (!rangeMatch) {
			continue;
		}

		if (!rangeMatches(rangeMatch[1], sortedPoints)) {
			continue;
		}

		const rewrittenBlock = block.replaceAll(
			'url("./',
			'url("../../node_modules/@chinese-fonts/lxgwwenkaibright/dist/LXGWBright-Light/',
		);
		keptBlocks.push(rewrittenBlock);
	}

	if (keptBlocks.length === 0) {
		throw new Error("No LXGW Bright Light subsets matched the current site text.");
	}

	const output = [
		"/* Auto-generated by scripts/generate-lxgw-font-subset.mjs. */",
		"/* Do not edit manually; rerun `pnpm font:subset` after changing site copy. */",
		...keptBlocks,
		"",
	].join("\n");

	await fs.writeFile(outputCssPath, output, "utf8");
	console.log(
		`Generated ${path.relative(repoRoot, outputCssPath)} with ${keptBlocks.length}/${blocks.length} font subsets.`,
	);
}

await main();
