<script>
import { onMount } from "svelte";
import { cubicOut } from "svelte/easing";
import { Tween } from "svelte/motion";
import { i18n } from "@/i18n/translation";
import I18nKey from "@/i18n/i18nKey";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const UPDATE_INTERVAL = 10;
const ANIMATION_DURATION = 5000;

function calculateProgress() {
	const now = new Date();
	const curYear = now.getFullYear();

	const startY = new Date(curYear, 0, 1).getTime();
	const endY = new Date(curYear + 1, 0, 1).getTime();
	const yProg = ((now.getTime() - startY) / (endY - startY)) * 100;

	const startD = new Date(curYear, now.getMonth(), now.getDate()).getTime();
	const endD = new Date(curYear, now.getMonth(), now.getDate() + 1).getTime();
	const dProg = ((now.getTime() - startD) / (endD - startD)) * 100;

	const dayOfYear =
		Math.floor(
			(Date.UTC(curYear, now.getMonth(), now.getDate()) -
				Date.UTC(curYear, 0, 1)) /
				MS_PER_DAY,
		) + 1;

	const centuryStart = new Date(2000, 0, 1).getTime();
	const centuryEnd = new Date(2100, 0, 1).getTime();
	const centuryProg =
		((now.getTime() - centuryStart) / (centuryEnd - centuryStart)) * 100;

	const BLOG_START_DATE = new Date("2025-10-01T00:00:00");
	const BLOG_END_DATE = new Date("2035-10-01T00:00:00");

	const blogTotal = BLOG_END_DATE.getTime() - BLOG_START_DATE.getTime();
	const blogElapsed = now.getTime() - BLOG_START_DATE.getTime();
	const blogProgVal = Math.max(0, (blogElapsed / blogTotal) * 100);

	return { yProg, dProg, dayOfYear, curYear, centuryProg, now, blogProgVal };
}

function formatPercent(v) {
	return Number.isFinite(v) ? `${v.toFixed(5)}%` : "0.00000%";
}

const loveStartDate = null;

const yProg = new Tween(0, {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});
const dProg = new Tween(0, {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});
const dayOfYear = new Tween(0, {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});
const curYear = new Tween(new Date().getFullYear(), {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});
const centuryProg = new Tween(0, {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});
const loveDays = new Tween(0, {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});
const blogProg = new Tween(0, {
	duration: ANIMATION_DURATION,
	easing: cubicOut,
});

onMount(() => {
	const initial = calculateProgress();

	yProg.set(initial.yProg);
	dProg.set(initial.dProg);
	dayOfYear.set(initial.dayOfYear);
	curYear.set(initial.curYear);
	centuryProg.set(initial.centuryProg);

	if (loveStartDate) {
		const loveDaysVal =
			(initial.now.getTime() - loveStartDate.getTime()) / MS_PER_DAY;
		loveDays.set(loveDaysVal);
	}

	blogProg.set(initial.blogProgVal);

	const interval = setInterval(() => {
		const current = calculateProgress();
		const options = { duration: 0 };

		yProg.set(current.yProg, options);
		dProg.set(current.dProg, options);
		dayOfYear.set(current.dayOfYear, options);
		curYear.set(current.curYear, options);
		centuryProg.set(current.centuryProg, options);

		if (loveStartDate) {
			const newLoveDays =
				(current.now.getTime() - loveStartDate.getTime()) / MS_PER_DAY;
			loveDays.set(newLoveDays, options);
		}

		blogProg.set(current.blogProgVal, options);
	}, UPDATE_INTERVAL);

	return () => clearInterval(interval);
});
</script>

<ul>
  <li>
    {i18n(I18nKey.timelineTodayIs)} <span class="time-number">{Math.round(dayOfYear.current)}</span>
    {i18n(I18nKey.timelineDayOf)}
    <span class="time-number">{Math.round(curYear.current)}</span>
  </li>
  <li>
    {i18n(I18nKey.timelineCenturyProgress)} <span class="time-number"
      >{formatPercent(centuryProg.current)}</span
    >
  </li>
  <li>
    {i18n(I18nKey.timelineYearProgress)} <span class="time-number"
      >{formatPercent(yProg.current)}</span
    >
  </li>
  <li>
    {i18n(I18nKey.timelineDayProgress)} <span class="time-number">{formatPercent(dProg.current)}</span
    >
  </li>
  <hr />
  <center>
    <div style="margin-bottom: 0.5rem; font-size: 0.9rem;">
      <a href="https://www.foreverblog.cn/blog/7063.html">「{i18n(I18nKey.timelineTenYearPledge)}」</a>{i18n(I18nKey.timelineFulfilled)}
      <span class="time-number">{formatPercent(blogProg.current)}</span>
    </div>
    {#if loveStartDate}
      <span class="time-number" style="font-size: 0.95rem;"
        >{Math.floor(loveDays.current)}</span
      > {i18n(I18nKey.timelineLoveDays)}
    {:else}
      <span class="time-number" style="font-size: 0.95rem;"
        >{i18n(I18nKey.timelineWaitingForYou)}</span
      >
    {/if}
  </center>
</ul>

<style>
  .time-number {
    display: inline-block;
    font-feature-settings: "tnum";
    font-variant-numeric: tabular-nums;
    font-weight: 600;
    color: var(--primary);
    min-width: 2.5em;
    text-align: center;
  }
</style>
