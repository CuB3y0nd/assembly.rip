import { type CollectionEntry, getCollection } from "astro:content";
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import { getCategoryUrl } from "@utils/url-utils.ts";

type PostEntry = CollectionEntry<"posts">;

export type PostForList = {
	slug: string;
	data: PostEntry["data"];
};

export type Tag = {
	name: string;
	count: number;
};

export type Category = {
	name: string;
	count: number;
	url: string;
};

let allPostsPromise: Promise<PostEntry[]> | undefined;
let sortedPostsPromise: Promise<PostEntry[]> | undefined;
let tagListPromise: Promise<Tag[]> | undefined;
let categoryListPromise: Promise<Category[]> | undefined;

function shouldIncludePost({ data }: PostEntry) {
	return !import.meta.env.PROD || data.draft !== true;
}

function sortPostsByPublishedDateDesc(a: PostEntry, b: PostEntry) {
	return b.data.published.getTime() - a.data.published.getTime();
}

async function getAllPosts() {
	allPostsPromise ??= getCollection("posts", shouldIncludePost);
	return allPostsPromise;
}

export async function getSortedPosts(): Promise<PostEntry[]> {
	sortedPostsPromise ??= getAllPosts().then((posts) => {
		const sortedPosts = [...posts].sort(sortPostsByPublishedDateDesc);

		return sortedPosts.map((post, index) => {
			const newerPost = sortedPosts[index - 1];
			const olderPost = sortedPosts[index + 1];

			return {
				...post,
				data: {
					...post.data,
					nextSlug: newerPost?.id ?? "",
					nextTitle: newerPost?.data.title ?? "",
					prevSlug: olderPost?.id ?? "",
					prevTitle: olderPost?.data.title ?? "",
				},
			};
		});
	});

	return sortedPostsPromise;
}

export async function getSortedPostsList(): Promise<PostForList[]> {
	const sortedPosts = await getSortedPosts();

	return sortedPosts.map((post) => ({
		slug: post.id,
		data: post.data,
	}));
}

export async function getTagList(): Promise<Tag[]> {
	tagListPromise ??= getAllPosts().then((posts) => {
		const tagCounts = new Map<string, number>();

		for (const post of posts) {
			for (const tag of post.data.tags) {
				tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
			}
		}

		return Array.from(tagCounts.entries())
			.sort(([left], [right]) =>
				left.toLowerCase().localeCompare(right.toLowerCase()),
			)
			.map(([name, count]) => ({ name, count }));
	});

	return tagListPromise;
}

export async function getCategoryList(): Promise<Category[]> {
	categoryListPromise ??= getAllPosts().then((posts) => {
		const uncategorizedLabel = i18n(I18nKey.uncategorized);
		const categoryCounts = new Map<string, number>();

		for (const post of posts) {
			const rawCategory = post.data.category;
			const categoryName =
				typeof rawCategory === "string" && rawCategory.trim() !== ""
					? rawCategory.trim()
					: uncategorizedLabel;

			categoryCounts.set(
				categoryName,
				(categoryCounts.get(categoryName) ?? 0) + 1,
			);
		}

		return Array.from(categoryCounts.entries())
			.sort(([left], [right]) =>
				left.toLowerCase().localeCompare(right.toLowerCase()),
			)
			.map(([name, count]) => ({
				name,
				count,
				url: getCategoryUrl(name),
			}));
	});

	return categoryListPromise;
}
