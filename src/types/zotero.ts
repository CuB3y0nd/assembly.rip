export interface ZoteroItem {
	key: string;
	version: number;
	library: {
		type: string;
		id: number;
		name: string;
		links: {
			alternate: {
				href: string;
				type: string;
			};
		};
	};
	links: {
		self: {
			href: string;
			type: string;
		};
		alternate: {
			href: string;
			type: string;
		};
	};
	meta: {
		creatorSummary?: string;
		parsedDate?: string;
		numChildren?: number;
	};
	data: {
		key: string;
		version: number;
		itemType: string;
		title: string;
		creators?: Array<{
			creatorType: string;
			firstName?: string;
			lastName?: string;
			name?: string;
		}>;
		abstractNote?: string;
		date?: string;
		publisher?: string;
		publicationTitle?: string;
		volume?: string;
		issue?: string;
		pages?: string;
		DOI?: string;
		ISBN?: string;
		url?: string;
		tags?: Array<{
			tag: string;
			type: number;
		}>;
		collections?: string[];
		dateAdded: string;
		dateModified: string;
	};
}

export interface ZoteroResponse {
	data: ZoteroItem[];
}
