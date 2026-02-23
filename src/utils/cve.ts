import type {
	CveContainer,
	CveDescription,
	CveReference,
	NvdCve,
	Severity,
} from "@/types/cve";

export interface CveData {
	state: string;
	assigner: string;
	affected: string;
	displayDesc: string;
	cvssScore: number | null;
	cvssVersion: string;
	severity: Severity;
	cwes: string[];
	tags: string[];
	refCount: number;
	dates: { published: string; updated: string };
}

function smartFormat(str: string) {
	if (!str || str.toLowerCase() === "n/a") return "";
	return str
		.split(/[-_ ]/)
		.map((word) => {
			if (/^\[.*\]$/.test(word)) return word.toUpperCase();
			return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
		})
		.join(" ");
}

export async function fetchCveData(
	id: string,
	fallbackDesc = "",
): Promise<CveData | null> {
	try {
		const mitreResp = await fetch(`https://cveawg.mitre.org/api/cve/${id}`);
		const mitreJson = await mitreResp.json();

		let nvdCve: NvdCve | null = null;
		try {
			const nvdResp = await fetch(
				`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`,
			);
			if (nvdResp.ok) {
				const nvdData = await nvdResp.json();
				if (nvdData.vulnerabilities?.length > 0)
					nvdCve = nvdData.vulnerabilities[0].cve;
			}
		} catch {
			/* ignore */
		}

		let state = "PENDING";
		let assigner = "";
		let affected = "";
		let displayDesc = fallbackDesc;
		let cvssScore: number | null = null;
		let cvssVersion = "";
		let severity: Severity = "none";
		let cwes: string[] = [];
		let tags: string[] = [];
		let refCount = 0;
		const dates = { published: "", updated: "" };

		if (mitreJson.error === "CVE_RECORD_DNE") {
			const idResp = await fetch(`https://cveawg.mitre.org/api/cve-id/${id}`);
			const idJson = await idResp.json();
			state = (idJson.state || "RESERVED").toUpperCase();
			assigner = smartFormat(idJson.owning_cna || "");
			affected = "Pending Disclosure";
		} else {
			state = (mitreJson.cveMetadata?.state || "PUBLISHED").toUpperCase();
			assigner = smartFormat(mitreJson.cveMetadata?.assignerShortName || "");

			const extractAff = (c: CveContainer) => {
				const list = c?.affected || [];
				for (const item of list) {
					const v =
						item.vendor && item.vendor !== "n/a"
							? smartFormat(item.vendor)
							: "";
					const p = item.product && item.product !== "n/a" ? item.product : "";
					if (v || p)
						return v && p
							? p.toLowerCase().includes(v.toLowerCase())
								? p
								: `${v} ${p}`
							: v || p;
				}
				return null;
			};

			let affRes = extractAff(mitreJson.containers?.cna);
			if (!affRes && mitreJson.containers?.adp) {
				for (const a of mitreJson.containers.adp) {
					affRes = extractAff(a);
					if (affRes) break;
				}
			}

			// NVD CPE Fallback - More robust check
			if (!affRes && nvdCve?.configurations) {
				for (const config of nvdCve.configurations) {
					if (config.nodes) {
						for (const node of config.nodes) {
							if (node.cpeMatch && node.cpeMatch.length > 0) {
								const cpe = node.cpeMatch[0].criteria;
								if (cpe) {
									const parts = cpe.split(":");
									if (parts.length > 4) {
										affRes = `${smartFormat(parts[3])} ${smartFormat(parts[4])}`;
										break;
									}
								}
							}
						}
					}
					if (affRes) break;
				}
			}
			affected = affRes || "Unknown";

			const mitreDesc = mitreJson.containers?.cna?.descriptions?.find(
				(d: CveDescription) =>
					d.lang === "en" && !d.value.toUpperCase().includes("RESERVED"),
			)?.value;
			const nvdDesc = nvdCve?.descriptions?.find(
				(d: CveDescription) => d.lang === "en",
			)?.value;
			displayDesc = mitreDesc || nvdDesc || displayDesc;

			let best: { val: number; ver: string; sev: string } | null = null;
			const updateBest = (val: number, ver: string, sev: string) => {
				const curPow = Number.parseFloat(ver);
				const bestPow = best ? Number.parseFloat(best.ver) : 0;
				if (
					curPow > bestPow ||
					(curPow === bestPow && val > (best?.val || 0))
				) {
					best = { val, ver, sev };
				}
			};

			const scanMitre = (c: CveContainer) => {
				c?.metrics?.forEach((m) => {
					if (m.cvssV4_0)
						updateBest(m.cvssV4_0.baseScore, "4.0", m.cvssV4_0.baseSeverity);
					else if (m.cvssV3_1)
						updateBest(m.cvssV3_1.baseScore, "3.1", m.cvssV3_1.baseSeverity);
					else if (m.cvssV3_0)
						updateBest(m.cvssV3_0.baseScore, "3.0", m.cvssV3_0.baseSeverity);
					else if (m.cvssV2_0)
						updateBest(m.cvssV2_0.baseScore, "2.0", m.cvssV2_0.baseSeverity);
				});
			};
			scanMitre(mitreJson.containers?.cna);
			mitreJson.containers?.adp?.forEach((a: CveContainer) => {
				scanMitre(a);
			});

			if (nvdCve?.metrics) {
				const nm = nvdCve.metrics;
				nm.cvssMetricV40?.forEach((i) => {
					updateBest(
						i.cvssData.baseScore,
						"4.0",
						i.cvssData.baseSeverity || "",
					);
				});
				nm.cvssMetricV31?.forEach((i) => {
					updateBest(
						i.cvssData.baseScore,
						"3.1",
						i.cvssData.baseSeverity || "",
					);
				});
				nm.cvssMetricV30?.forEach((i) => {
					updateBest(
						i.cvssData.baseScore,
						"3.0",
						i.cvssData.baseSeverity || "",
					);
				});
				nm.cvssMetricV2?.forEach((i) => {
					updateBest(
						i.cvssData.baseScore,
						"2.0",
						i.baseSeverity || i.cvssData.baseSeverity || "",
					);
				});
			}

			if (best) {
				cvssScore = best.val;
				cvssVersion = best.ver;
				severity = best.sev.toLowerCase() as Severity;
			}

			const cweSet = new Set<string>();
			const extMitre = (c: CveContainer) => {
				c?.problemTypes?.forEach((pt) => {
					pt.descriptions?.forEach((d) => {
						if (d.cweId) cweSet.add(d.cweId);
						else if (d.description?.startsWith("CWE-"))
							cweSet.add(d.description);
					});
				});
			};
			extMitre(mitreJson.containers?.cna);
			mitreJson.containers?.adp?.forEach((a: CveContainer) => {
				extMitre(a);
			});
			nvdCve?.weaknesses?.forEach((w) => {
				w.description?.forEach((d) => {
					if (d.value?.startsWith("CWE-")) cweSet.add(d.value);
				});
			});
			cwes = Array.from(cweSet);

			const urlSet = new Set<string>();
			const tagSet = new Set<string>();
			const col = (refs: CveReference[] | undefined) => {
				refs?.forEach((r) => {
					if (!r.url) return;
					const cleanUrl = r.url.split(/[?#]/)[0].replace(/\/$/, "");
					urlSet.add(cleanUrl);
					const u = r.url.toLowerCase();
					const t = (r.tags || []).map((s) => s.toLowerCase());
					if (t.includes("exploit") || u.includes("exploit"))
						tagSet.add("Exploit");
					if (t.includes("poc") || u.includes("poc")) tagSet.add("PoC");
					if (
						t.includes("advisory") ||
						t.includes("third party advisory") ||
						u.includes("advisory")
					)
						tagSet.add("Advisory");
				});
			};
			col(mitreJson.containers?.cna?.references);
			mitreJson.containers?.adp?.forEach((a: CveContainer) => {
				col(a.references);
			});
			col(nvdCve?.references);
			refCount = urlSet.size;
			tags = Array.from(tagSet);

			if (mitreJson.cveMetadata?.datePublished)
				dates.published = mitreJson.cveMetadata.datePublished.split("T")[0];
			else if (nvdCve?.published)
				dates.published = nvdCve.published.split("T")[0];
			if (mitreJson.cveMetadata?.dateUpdated)
				dates.updated = mitreJson.cveMetadata.dateUpdated.split("T")[0];
			else if (nvdCve?.lastModified)
				dates.updated = nvdCve.lastModified.split("T")[0];
		}

		return {
			state,
			assigner,
			affected,
			displayDesc,
			cvssScore,
			cvssVersion,
			severity,
			cwes,
			tags,
			refCount,
			dates,
		};
	} catch (e) {
		console.error(`[CVE] ${id} fetch error:`, e);
		return null;
	}
}
