export interface CveDescription {
	lang: string;
	value: string;
}

export interface CveMetric {
	cvssV4_0?: { baseScore: number; baseSeverity: string };
	cvssV3_1?: { baseScore: number; baseSeverity: string };
	cvssV3_0?: { baseScore: number; baseSeverity: string };
	cvssV2_0?: { baseScore: number; baseSeverity: string };
}

export interface CveAffected {
	vendor?: string;
	product?: string;
}

export interface CveReference {
	url: string;
	tags?: string[];
}

export interface CveContainer {
	affected?: CveAffected[];
	descriptions?: CveDescription[];
	metrics?: CveMetric[];
	problemTypes?: {
		descriptions: { cweId?: string; description?: string }[];
	}[];
	references?: CveReference[];
}

export interface NvdCvssData {
	baseScore: number;
	baseSeverity?: string;
}

export interface NvdMetricItem {
	cvssData: NvdCvssData;
	baseSeverity?: string;
}

export interface NvdCve {
	id: string;
	sourceIdentifier?: string;
	published?: string;
	lastModified?: string;
	descriptions?: CveDescription[];
	metrics?: {
		cvssMetricV40?: NvdMetricItem[];
		cvssMetricV31?: NvdMetricItem[];
		cvssMetricV30?: NvdMetricItem[];
		cvssMetricV2?: NvdMetricItem[];
	};
	weaknesses?: {
		description: { value: string }[];
	}[];
	references?: CveReference[];
	configurations?: {
		nodes?: {
			cpeMatch?: { criteria: string }[];
		}[];
	}[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "none";
