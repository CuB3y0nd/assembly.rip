export interface GithubRepoData {
	repo: string;
	owner: string;
	name: string;
	description: string;
	language: string;
	stars: string;
	forks: string;
	license: string;
	avatarUrl: string;
	available: boolean;
}

type GithubRepoApiResponse = {
	description?: string | null;
	forks_count?: number;
	stargazers_count?: number;
	language?: string | null;
	license?: {
		spdx_id?: string | null;
	} | null;
	owner?: {
		login?: string | null;
		avatar_url?: string | null;
	} | null;
};

const FETCH_TIMEOUT_MS = 8000;
const githubRequestCache = new Map<string, Promise<GithubRepoData>>();

function splitRepo(repo: string) {
	const [owner, name, ...rest] = repo.trim().split("/");

	if (!owner || !name || rest.length > 0) {
		throw new Error(`Invalid GitHub repository: ${repo}`);
	}

	return { owner, name };
}

function formatCompactNumber(value: number | undefined) {
	if (typeof value !== "number" || Number.isNaN(value)) {
		return "--";
	}

	return new Intl.NumberFormat("en-US", {
		notation: "compact",
		maximumFractionDigits: 1,
	})
		.format(value)
		.replaceAll("\u202f", "");
}

function sanitizeDescription(description: string | null | undefined) {
	const normalized = description?.replace(/:[a-zA-Z0-9_+-]+:/g, "").trim();
	return normalized || "Description not set";
}

function createFallbackRepoData(repo: string): GithubRepoData {
	const { owner, name } = splitRepo(repo);

	return {
		repo,
		owner,
		name,
		description: "Repository metadata unavailable during build.",
		language: "Unknown",
		stars: "--",
		forks: "--",
		license: "unknown",
		avatarUrl: "",
		available: false,
	};
}

export async function fetchGithubRepoData(
	repo: string,
): Promise<GithubRepoData> {
	const normalizedRepo = repo.trim();
	const cached = githubRequestCache.get(normalizedRepo);

	if (cached) {
		return cached;
	}

	const request = loadGithubRepoData(normalizedRepo);
	githubRequestCache.set(normalizedRepo, request);

	return request;
}

async function loadGithubRepoData(repo: string): Promise<GithubRepoData> {
	const { owner, name } = splitRepo(repo);
	const githubToken = process.env.GITHUB_TOKEN?.trim() ?? "";
	const headers = new Headers({
		Accept: "application/vnd.github+json",
		"User-Agent": "assembly.rip",
	});

	if (githubToken) {
		headers.set("Authorization", `Bearer ${githubToken}`);
	}

	try {
		const response = await fetch(`https://api.github.com/repos/${repo}`, {
			headers,
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
		});

		if (!response.ok) {
			throw new Error(`Request failed: ${response.status} ${repo}`);
		}

		const data = (await response.json()) as GithubRepoApiResponse;
		const license =
			data.license?.spdx_id && data.license.spdx_id !== "NOASSERTION"
				? data.license.spdx_id
				: "no-license";

		return {
			repo,
			owner: data.owner?.login?.trim() || owner,
			name,
			description: sanitizeDescription(data.description),
			language: data.language?.trim() || "Unknown",
			stars: formatCompactNumber(data.stargazers_count),
			forks: formatCompactNumber(data.forks_count),
			license,
			avatarUrl: data.owner?.avatar_url?.trim() || "",
			available: true,
		};
	} catch {
		return createFallbackRepoData(repo);
	}
}
