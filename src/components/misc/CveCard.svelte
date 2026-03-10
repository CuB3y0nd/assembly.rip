<script lang="ts">
import { onMount } from "svelte";
import I18nKey from "@/i18n/i18nKey";
import { i18n } from "@/i18n/translation";
import type { Severity } from "@/types/cve";
import { fetchCveData } from "@/utils/cve";

export let id: string;
export let desc = "";

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

async function loadCveData() {
	const data = await fetchCveData(id, desc);
	if (data) {
		state = data.state;
		assigner = data.assigner;
		affected = data.affected;
		displayDesc = data.displayDesc;
		cvssScore = data.cvssScore;
		cvssVersion = data.cvssVersion;
		severity = data.severity;
		cwes = data.cwes;
		tags = data.tags;
		refCount = data.refCount;
		dates = data.dates;
	}
	loading = false;
}

onMount(loadCveData);
</script>

<div class="cve-anchor">
  <a
    href="https://www.cve.org/CVERecord?id={id}"
    target="_blank"
    class="cve-card-main"
    class:loading
  >
    <div class="inner-layout">
      <!-- Data Column -->
      <div class="data-pane">
        <div class="title-line">
          <span class="cve-id">{id}</span>
          <div class="tags-row">
            {#if state === "RESERVED"}<span class="badge rsvd">{i18n(I18nKey.cveReserved)}</span
              >{/if}
            {#each cwes as cwe}<span class="badge cwe">{cwe}</span>{/each}
            {#each tags as tag}<span class="badge tag-{tag.toLowerCase()}"
                >{tag}</span
              >{/each}
          </div>
        </div>

        <p class="description">
          {displayDesc ||
            (loading
              ? i18n(I18nKey.cveAggregating)
              : i18n(I18nKey.cveReservedInfo))}
        </p>

        <div class="metadata-line">
          <div class="meta-box">
            <span class="label">{i18n(I18nKey.cveProduct)}</span><span class="value bold"
              >{affected || (loading ? "..." : i18n(I18nKey.cveNone))}</span
            >
          </div>
          <div class="meta-box">
            <span class="label">{i18n(I18nKey.cveAssigner)}</span><span class="value"
              >{assigner || (loading ? "..." : i18n(I18nKey.cveNone))}</span
            >
          </div>
          <div class="meta-box">
            <span class="label">{i18n(I18nKey.cvePublished)}</span><span class="value"
              >{dates.published || (loading ? "..." : i18n(I18nKey.cveNone))}</span
            >
          </div>
          <div class="meta-box">
            <span class="label">{i18n(I18nKey.cveUpdated)}</span><span class="value"
              >{dates.updated || (loading ? "..." : i18n(I18nKey.cveNone))}</span
            >
          </div>
          {#if refCount > 0}<div class="ref-counter">{refCount} {i18n(I18nKey.cveRefs)}</div>{/if}
        </div>
      </div>

      <!-- Score Column -->
      <div class="score-pane" style="--sev-color: {severityColors[severity]}">
        {#if state === "RESERVED" && cvssScore === null}
          <div class="rsvd-title">{i18n(I18nKey.cveReserved)}</div>
        {:else}
          <div class="cvss-v">CVSS {cvssVersion || "N/A"}</div>
          <div class="cvss-n">
            {cvssScore !== null ? cvssScore.toFixed(1) : "--"}
          </div>
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
    padding: 12px; /* Reserved space for hover shadow */
    box-sizing: border-box;
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
    content: "";
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
    background: linear-gradient(
      135deg,
      var(--card-bg),
      rgba(var(--primary-rgb), 0.015)
    );
  }

  .cve-card-main:hover::after {
    border-color: var(--primary);
    box-shadow:
      0 0 0 2px rgba(var(--primary-rgb), 0.1),
      0 15px 35px -12px rgba(0, 0, 0, 0.2);
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
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 0.65rem;
    font-weight: 800;
    height: 1.4rem;
    padding: 0 0.55rem;
    border-radius: 0.35rem;
    text-transform: uppercase;
    white-space: nowrap;
    border: 1px solid var(--line-divider);
    line-height: 1;
    transform: translateY(0.5px);
  }

  .rsvd {
    color: #f59e0b;
    border-color: rgba(245, 158, 11, 0.3);
    background: rgba(245, 158, 11, 0.04);
  }
  .cwe {
    color: var(--primary);
    border-color: rgba(var(--primary-rgb), 0.2);
    background: rgba(var(--primary-rgb), 0.04);
  }
  .tag-exploit {
    color: #ef4444;
    border-color: rgba(239, 68, 68, 0.2);
    background: rgba(239, 68, 68, 0.04);
  }
  .tag-poc {
    color: #8b5cf6;
    border-color: rgba(139, 92, 246, 0.2);
    background: rgba(139, 92, 246, 0.04);
  }
  .tag-advisory {
    color: #0ea5e9;
    border-color: rgba(14, 165, 233, 0.2);
    background: rgba(14, 165, 233, 0.04);
  }
  .type-badge {
    color: var(--text-50);
    background: var(--btn-regular-bg);
  }

  .description {
    font-size: 0.95rem;
    line-height: 1.7;
    color: var(--text-75);
    margin: 0;
    display: -webkit-box;
    -line-clamp: 2;
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
  .label {
    font-size: 0.55rem;
    font-weight: 850;
    color: var(--text-30);
    letter-spacing: 0.06em;
  }
  .value {
    font-size: 0.85rem;
    font-weight: 700;
    color: var(--text-50);
    font-family: var(--font-mono);
  }
  .value.bold {
    color: var(--text-75);
    font-weight: 850;
  }

  .ref-counter {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    font-weight: 700;
    color: var(--text-30);
    background: var(--btn-regular-bg);
    display: inline-flex;
    align-items: center;
    height: 1.4rem;
    padding: 0 0.6rem;
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

  .cvss-v {
    font-size: 0.7rem;
    font-weight: 850;
    color: var(--text-30);
    margin-bottom: 0.4rem;
  }
  .cvss-n {
    font-family: var(--font-mono);
    font-size: 3rem;
    font-weight: 950;
    line-height: 0.85;
    color: var(--sev-color);
    letter-spacing: -0.05em;
  }
  .cvss-l {
    font-size: 0.85rem;
    font-weight: 900;
    margin-top: 0.6rem;
    color: var(--sev-color);
    letter-spacing: 0.05em;
  }
  .rsvd-title {
    font-family: var(--font-mono);
    font-size: 1.4rem;
    font-weight: 950;
    color: var(--text-25);
    text-align: center;
  }

  .loading {
    opacity: 0.6;
    pointer-events: none;
  }

  @media (max-width: 768px) {
    .inner-layout {
      grid-template-columns: 1fr;
    }
    .data-pane {
      border-right: none;
      border-bottom: 2px solid var(--line-color);
    }
    .score-pane {
      flex-direction: row;
      justify-content: center;
      align-items: center;
      gap: 1.5rem;
      padding: 1.25rem 1.5rem;
      min-height: 5rem;
    }
    .cvss-v {
      margin-bottom: 0;
    }
    .cvss-l {
      margin-top: 0;
    }
  }
</style>
