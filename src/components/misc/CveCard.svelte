<script lang="ts">
import { onMount } from "svelte";

export let id: string;
export let desc = "";

// 定义 CVE API 相关的接口以移除 any
interface CveDescription {
	lang: string;
	value: string;
}

interface CveMetric {
	cvssV3_1?: { baseScore: number; baseSeverity: string };
	cvssV3_0?: { baseScore: number; baseSeverity: string };
	cvssV2_0?: { baseScore: number; baseSeverity: string };
}

interface CveAffected {
	vendor?: string;
	product?: string;
}

interface CveReference {
	url: string;
	tags?: string[];
}

interface CveContainer {
	affected?: CveAffected[];
	descriptions?: CveDescription[];
	metrics?: CveMetric[];
	problemTypes?: {
		descriptions: { cweId?: string; description?: string }[];
	}[];
	references?: CveReference[];
}

type Severity = "critical" | "high" | "medium" | "low" | "none";

let loading = true;
let state = "PENDING";
let assigner = "";
let affected = "";
let displayDesc = desc;
let cvssScore: number | null = null;
let cvssVersion = "";
let severity: Severity = "none";
let cwes: string[] = [];
let tags: string[] = [];
let refCount = 0;
let dates = { published: "", updated: "" };

const severityColors: Record<Severity, string> = {
	critical: "#ef4444",
	high: "#f97316",
	medium: "#f59e0b",
	low: "#10b981",
	none: "#6b7280",
};

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

async function fetchCve() {
	try {
		const resp = await fetch(`https://cveawg.mitre.org/api/cve/${id}`);
		const json = await resp.json();

		if (json.error === "CVE_RECORD_DNE") {
			const idResp = await fetch(`https://cveawg.mitre.org/api/cve-id/${id}`);
			const idJson = await idResp.json();
			state = (idJson.state || "RESERVED").toUpperCase();
			assigner = smartFormat(idJson.owning_cna || "");
			affected = "Pending Disclosure";
		} else {
			state = (json.cveMetadata?.state || "PUBLISHED").toUpperCase();
			assigner = smartFormat(json.cveMetadata?.assignerShortName || "");

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

			let affRes = extractAff(json.containers?.cna);
			if (!affRes && json.containers?.adp) {
				for (const a of json.containers.adp) {
					affRes = extractAff(a);
					if (affRes) break;
				}
			}
			affected = affRes || "Unknown";

			const apiDesc = json.containers?.cna?.descriptions?.find(
				(d: CveDescription) =>
					d.lang === "en" && !d.value.toUpperCase().includes("RESERVED"),
			)?.value;
			if (apiDesc) displayDesc = apiDesc;

			let best: { val: number; ver: string; sev: string } | null = null;
			const scan = (c: CveContainer) => {
				c?.metrics?.forEach((m) => {
					const v = m.cvssV3_1 || m.cvssV3_0 || m.cvssV2_0;
					if (v) {
						const ver = m.cvssV3_1 ? "3.1" : m.cvssV3_0 ? "3.0" : "2.0";
						if (
							!best ||
							Number.parseFloat(ver) > Number.parseFloat(best.ver) ||
							(ver === best.ver && v.baseScore > best.val)
						) {
							best = {
								val: v.baseScore,
								ver,
								sev: v.baseSeverity || "UNKNOWN",
							};
						}
					}
				});
			};
			scan(json.containers?.cna);
			json.containers?.adp?.forEach((adp: CveContainer) => {
				scan(adp);
			});
			if (best) {
				cvssScore = best.val;
				cvssVersion = best.ver;
				severity = best.sev.toLowerCase() as Severity;
			}

			const cweSet = new Set<string>();
			const ext = (c: CveContainer) => {
				c?.problemTypes?.forEach((pt) => {
					pt.descriptions?.forEach((d) => {
						if (d.cweId) cweSet.add(d.cweId);
						else if (d.description?.startsWith("CWE-"))
							cweSet.add(d.description);
					});
				});
			};
			ext(json.containers?.cna);
			json.containers?.adp?.forEach((adp: CveContainer) => {
				ext(adp);
			});
			cwes = Array.from(cweSet);

			const urlSet = new Set<string>();
			const tagSet = new Set<string>();
			const col = (refs: CveReference[] | undefined) => {
				refs?.forEach((r) => {
					if (!r.url) return;
					urlSet.add(r.url.split(/[?#]/)[0].replace(/\/$/, ""));
					const u = r.url.toLowerCase();
					if (u.includes("exploit") || r.tags?.includes("exploit"))
						tagSet.add("Exploit");
					if (u.includes("poc") || r.tags?.includes("poc")) tagSet.add("PoC");
					if (u.includes("advisory") || u.includes("github.com/advisories"))
						tagSet.add("Advisory");
				});
			};
			col(json.containers?.cna?.references);
			json.containers?.adp?.forEach((a: CveContainer) => {
				col(a.references);
			});
			refCount = urlSet.size;
			tags = Array.from(tagSet);

			if (json.cveMetadata?.datePublished)
				dates.published = json.cveMetadata.datePublished.split("T")[0];
			if (json.cveMetadata?.dateUpdated)
				dates.updated = json.cveMetadata.dateUpdated.split("T")[0];
		}
	} catch (e) {
		console.warn(`[CVE] ${id} err`);
	} finally {
		loading = false;
	}
}

onMount(fetchCve);
</script>

<div class="cve-anchor">
  <a href="https://www.cve.org/CVERecord?id={id}" target="_blank" class="cve-card-main" class:loading>
    <div class="inner-layout">
      <div class="data-pane">
        <div class="title-line">
          <span class="cve-id">{id}</span>
          <div class="tags-row">
            {#if state === 'RESERVED'}<span class="badge rsvd">RESERVED</span>{/if}
            {#each cwes as cwe}<span class="badge cwe">{cwe}</span>{/each}
            {#each tags as tag}<span class="badge tag-{tag.toLowerCase()}">{tag}</span>{/each}
          </div>
        </div>

        <p class="description">
          {displayDesc || (loading ? "Aggregating data..." : "Detailed information reserved by CNA. Public disclosure is pending.")}
        </p>

        <div class="metadata-line">
          <div class="meta-box"><span class="label">PRODUCT</span><span class="value bold">{affected || (loading ? "..." : "None")}</span></div>
          <div class="meta-box"><span class="label">ASSIGNER</span><span class="value">{assigner || (loading ? "..." : "None")}</span></div>
          <div class="meta-box"><span class="label">PUBLISHED</span><span class="value">{dates.published || (loading ? "..." : "None")}</span></div>
          <div class="meta-box"><span class="label">UPDATED</span><span class="value">{dates.updated || (loading ? "..." : "None")}</span></div>
          {#if refCount > 0}<div class="ref-counter">{refCount} Refs</div>{/if}
        </div>
      </div>

      <div class="score-pane" style="--sev-color: {severityColors[severity]}">
        {#if state === 'RESERVED' && cvssScore === null}
          <div class="rsvd-title">RESERVED</div>
        {:else}
          <div class="cvss-v">CVSS {cvssVersion}</div>
          <div class="cvss-n">{cvssScore !== null ? cvssScore.toFixed(1) : "--"}</div>
          <div class="cvss-l">{severity.toUpperCase()}</div>
        {/if}
      </div>
    </div>
  </a>
</div>

<style>
  .cve-anchor {
    margin: 2.5rem 0;
    width: 100%;
    display: flex;
  }

  .cve-card-main {
    position: relative;
    display: block;
    width: 100%;
    background: var(--card-bg);
    border-radius: 1rem;
    text-decoration: none !important;
    color: inherit !important;
    transition: all 0.3s cubic-bezier(0.23, 1, 0.32, 1);
    box-sizing: border-box;
  }

  .cve-card-main::after {
    content: '';
    position: absolute;
    inset: 0;
    border: 2px solid var(--line-color);
    border-radius: inherit;
    pointer-events: none;
    transition: inherit;
    z-index: 10;
  }

  .cve-card-main:hover {
    transform: translate(2px, -2px);
    box-shadow: -4px 8px 30px -10px rgba(0, 0, 0, 0.2);
    background: linear-gradient(135deg, var(--card-bg), rgba(var(--primary-rgb), 0.015));
  }

  .cve-card-main:hover::after {
    border-color: var(--primary);
    box-shadow: 0 0 0 2px rgba(var(--primary-rgb), 0.1);
  }

  .inner-layout {
    display: grid;
    grid-template-columns: 1fr 180px;
    width: 100%;
  }

  .data-pane {
    padding: 1.5rem 2rem;
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
    border-right: 2px solid var(--line-color);
    min-width: 0;
  }

  .title-line {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    flex-wrap: wrap;
  }

  .cve-id {
    font-family: var(--font-mono);
    font-size: 1.25rem;
    font-weight: 850;
    color: var(--primary);
    letter-spacing: -0.01em;
  }

  .tags-row {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .badge {
    font-size: 0.65rem;
    font-weight: 800;
    padding: 0.15rem 0.55rem;
    border-radius: 0.35rem;
    text-transform: uppercase;
    white-space: nowrap;
    border: 1px solid var(--line-divider);
    background: transparent;
  }

  .rsvd { color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.04); }
  .cwe { color: var(--primary); border-color: rgba(var(--primary-rgb), 0.2); background: rgba(var(--primary-rgb), 0.04); }
  .tag-exploit { color: #ef4444; border-color: rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.04); }
  .tag-poc { color: #8b5cf6; border-color: rgba(139, 92, 246, 0.2); background: rgba(139, 92, 246, 0.04); }
  .tag-advisory { color: #0ea5e9; border-color: rgba(14, 165, 233, 0.2); background: rgba(14, 165, 233, 0.04); }
  .type-badge { color: var(--text-50); background: var(--btn-regular-bg); }

  .description {
    font-size: 0.95rem;
    line-height: 1.7;
    color: var(--text-75);
    margin: 0;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    flex-grow: 1;
  }

  .metadata-line {
    display: flex;
    flex-wrap: wrap;
    gap: 1.75rem;
    margin-top: 0.5rem;
    align-items: center;
  }

  .meta-box {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .label { font-size: 0.55rem; font-weight: 850; color: var(--text-30); letter-spacing: 0.06em; }
  .value { font-size: 0.85rem; font-weight: 700; color: var(--text-50); font-family: var(--font-mono); }
  .value.bold { color: var(--text-75); font-weight: 850; }

  .ref-counter {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    font-weight: 700;
    color: var(--text-30);
    background: var(--btn-regular-bg);
    padding: 0.15rem 0.6rem;
    border-radius: 2rem;
  }

  .score-pane {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: rgba(var(--primary-rgb), 0.015);
    padding: 1.5rem;
    text-align: center;
  }

  .cvss-v { font-size: 0.7rem; font-weight: 850; color: var(--text-30); margin-bottom: 0.4rem; }
  .cvss-n { font-family: var(--font-mono); font-size: 3rem; font-weight: 950; line-height: 0.85; color: var(--sev-color); letter-spacing: -0.05em; }
  .cvss-l { font-size: 0.85rem; font-weight: 900; margin-top: 0.6rem; color: var(--sev-color); letter-spacing: 0.05em; }
  .rsvd-title { font-family: var(--font-mono); font-size: 1.4rem; font-weight: 950; color: var(--text-25); }

  .loading { opacity: 0.6; pointer-events: none; }

  @media (max-width: 768px) {
    .inner-layout { grid-template-columns: 1fr; }
    .data-pane { border-right: none; border-bottom: 2px solid var(--line-color); }
    .score-pane { flex-direction: row; gap: 2rem; padding: 1rem 1.75rem; }
  }
</style>
