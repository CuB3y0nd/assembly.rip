<script lang="ts">
import Icon from "@iconify/svelte";
import { onMount } from "svelte";

interface Post {
	slug: string;
	data: {
		title: string;
		tags: string[];
		category?: string | null;
		published: Date | string;
	};
}

export let posts: Post[] = [];

const now = new Date();
// 严格的 365 天前
const strictYearStart = new Date(now);
strictYearStart.setFullYear(now.getFullYear() - 1);
strictYearStart.setHours(0, 0, 0, 0);

// 用于网格对齐的日期（往前推到该周周日开始）
const gridStartDate = new Date(strictYearStart);
gridStartDate.setDate(gridStartDate.getDate() - gridStartDate.getDay());
gridStartDate.setHours(0, 0, 0, 0);

let scrollContainer: HTMLDivElement;

function formatDate(date: Date) {
	const y = date.getFullYear();
	const m = (date.getMonth() + 1).toString().padStart(2, "0");
	const d = date.getDate().toString().padStart(2, "0");
	return `${y}-${m}-${d}`;
}

// 统计逻辑：直接计算传入的所有文章总数
$: totalPosts = posts.length;

// 网格数据渲染：只展示过去一年的活跃点
$: counts = posts.reduce(
	(acc, post) => {
		const pDate = new Date(post.data.published);
		if (
			pDate.getTime() >= strictYearStart.getTime() &&
			pDate.getTime() <= now.getTime()
		) {
			const dateStr = formatDate(pDate);
			acc[dateStr] = (acc[dateStr] || 0) + 1;
		}
		return acc;
	},
	{} as Record<string, number>,
);

$: maxCount = Math.max(...Object.values(counts), 1);

$: weeks = (() => {
	const w = [];
	let currentWeek = [];
	const current = new Date(gridStartDate);
	const end = new Date(now);
	end.setHours(23, 59, 59, 999);

	while (current <= end) {
		const dateStr = formatDate(current);
		currentWeek.push({
			date: dateStr,
			count: counts[dateStr] || 0,
		});
		if (currentWeek.length === 7) {
			w.push(currentWeek);
			currentWeek = [];
		}
		current.setDate(current.getDate() + 1);
	}
	if (currentWeek.length > 0) {
		while (currentWeek.length < 7) {
			currentWeek.push({ date: "", count: -1 });
		}
		w.push(currentWeek);
	}
	return w;
})();

const monthNames = [
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
];

const WEEK_WIDTH = 18;

$: monthLabels = (() => {
	const labels = [];
	let lastMonth = -1;
	let lastWeekIndex = -1;
	for (let i = 0; i < weeks.length; i++) {
		if (weeks[i][0].date === "") continue;
		const date = new Date(weeks[i][0].date);
		const month = date.getMonth();
		if (month !== lastMonth && i - lastWeekIndex >= 3) {
			labels.push({ label: monthNames[month], weekIndex: i });
			lastMonth = month;
			lastWeekIndex = i;
		}
	}
	return labels;
})();

function getOpacity(count: number) {
	if (count <= 0) return 0;
	return 0.2 + (count / maxCount) * 0.8;
}

onMount(() => {
	if (scrollContainer) {
		const isOverflowing =
			scrollContainer.scrollWidth > scrollContainer.clientWidth;
		if (isOverflowing) {
			scrollContainer.scrollLeft = scrollContainer.scrollWidth;
		}
	}
});
</script>

<!-- Header: 左右对齐，显示总文章数 -->
<div
  class="flex items-end justify-between mb-4 px-1 text-black/75 dark:text-white/75 font-bold"
>
  <div class="flex items-center gap-2">
    <Icon
      icon="material-symbols:edit-calendar-outline-rounded"
      class="text-xl"
    />
    <span class="text-base">Activity</span>
  </div>
  <div class="text-[12px] opacity-40">
    Total published {totalPosts} posts
  </div>
</div>

<div class="w-full">
  <div
    bind:this={scrollContainer}
    class="overflow-x-auto hide-scrollbar scroll-smooth"
  >
    <div class="w-fit min-w-max pr-2">
      <!-- 月份标签 -->
      <div
        class="flex h-5 ml-12 mb-1 relative text-[12px] text-black/40 dark:text-white/40 font-bold"
      >
        {#each monthLabels as month}
          <div class="absolute" style="left: {month.weekIndex * WEEK_WIDTH}px">
            {month.label}
          </div>
        {/each}
      </div>

      <div class="flex flex-row relative">
        <!-- 星期标签列 -->
        <div
          class="sticky left-0 z-20 flex flex-col justify-between w-12 pr-3 text-[12px] text-black/30 dark:text-white/30 font-bold py-[4px] h-[122px] shrink-0 text-right bg-[var(--card-bg)]"
        >
          <span></span>
          <span>Mon</span>
          <span></span>
          <span>Wed</span>
          <span></span>
          <span>Fri</span>
          <span></span>
        </div>

        <!-- 热力图网格 -->
        <div class="flex flex-row gap-[4px] z-10">
          {#each weeks as week}
            <div class="flex flex-col gap-[4px]">
              {#each week as day}
                {#if day.count === -1}
                  <div class="w-[14px] h-[14px]"></div>
                {:else}
                  <div
                    class="w-[14px] h-[14px] rounded-[2px] transition-all duration-300 hover:ring-2 hover:ring-[var(--primary)] hover:ring-offset-1 hover:ring-offset-[var(--card-bg)]"
                    style="background-color: {day.count === 0
                      ? 'var(--btn-regular-bg)'
                      : 'var(--primary)'}; opacity: {day.count === 0
                      ? 1
                      : getOpacity(day.count)}"
                    title="{day.date}: {day.count} {day.count === 1
                      ? 'post'
                      : 'posts'}"
                  ></div>
                {/if}
              {/each}
            </div>
          {/each}
        </div>
      </div>

      <!-- 图例 (Legend) -->
      <div
        class="flex items-center justify-end mt-3 gap-1.5 text-[12px] text-black/30 dark:text-white/30 font-bold pr-2"
      >
        <span>Less</span>
        <div class="w-3 h-3 rounded-[1px] bg-[var(--btn-regular-bg)]"></div>
        <div class="w-3 h-3 rounded-[1px] bg-[var(--primary)] opacity-20"></div>
        <div class="w-3 h-3 rounded-[1px] bg-[var(--primary)] opacity-45"></div>
        <div class="w-3 h-3 rounded-[1px] bg-[var(--primary)] opacity-70"></div>
        <div
          class="w-3 h-3 rounded-[1px] bg-[var(--primary)] opacity-100"
        ></div>
        <span>More</span>
      </div>
    </div>
  </div>
</div>
