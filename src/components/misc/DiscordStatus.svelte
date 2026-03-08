<script lang="ts">
import { onMount } from "svelte";
import type { DiscordStatus } from "@/types/discord";
import { fetchDiscordStatus } from "@/utils/discord";
import { i18n } from "@/i18n/translation";
import I18nKey from "@/i18n/i18nKey";

let status: DiscordStatus = "loading";
let statusText = i18n(I18nKey.spotifyLoading); // Reuse spotify loading or use a new one

const statusColors: Record<DiscordStatus, string> = {
	online: "35, 165, 90",
	idle: "240, 178, 50",
	dnd: "242, 63, 67",
	offline: "128, 132, 142",
	loading: "128, 132, 142",
};

async function loadStatus() {
	const data = await fetchDiscordStatus();
	if (data?.success) {
		status = data.data.discord_status;
		const statusMap: Record<string, string> = {
			online: i18n(I18nKey.discordOnline),
			idle: i18n(I18nKey.discordIdle),
			dnd: i18n(I18nKey.discordDnd),
			offline: i18n(I18nKey.discordOffline),
		};
		statusText = statusMap[status] || i18n(I18nKey.discordOffline);
	} else {
		status = "offline";
		statusText = i18n(I18nKey.discordOffline);
	}
}

onMount(() => {
	loadStatus();
	const interval = setInterval(loadStatus, 30000);
	return () => clearInterval(interval);
});
</script>

<span class="discord-status-wrapper" title={statusText}>
  <span class="status-indicator" style="--rgb: {statusColors[status]}">
    <span class="glow-dynamic"></span>
    <span class="glow-static"></span>
    <span class="core"></span>
  </span>
</span>

<style>
  .discord-status-wrapper {
    display: inline-flex;
    align-items: center;
    vertical-align: middle;
    cursor: help;
    transform: translateY(-1px); /* Slight upward adjustment to compensate for code tag line-height alignment */
    margin-right: 2px;
  }

  .status-indicator {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
  }

  /* 半透明质感 */
  .core {
    width: 6px;
    height: 6px;
    background-color: rgba(var(--rgb), 0.7);
    border-radius: 50%;
    z-index: 3;
    box-shadow: 0 0 2px rgba(var(--rgb), 0.4);
  }

  /* 静态底色光晕：非常淡的扩散 */
  .glow-static {
    position: absolute;
    width: 10px;
    height: 10px;
    background-color: rgba(var(--rgb), 0.15);
    border-radius: 50%;
    filter: blur(2px);
    z-index: 2;
  }

  /* 动态扩散光晕：更柔和的膨胀 */
  .glow-dynamic {
    position: absolute;
    width: 100%;
    height: 100%;
    background-color: rgba(var(--rgb), 0.25);
    border-radius: 50%;
    filter: blur(3px);
    z-index: 1;
    animation: pulse-out 3s infinite cubic-bezier(0.4, 0, 0.6, 1);
  }

  @keyframes pulse-out {
    0% {
      transform: scale(0.5);
      opacity: 0.5;
    }
    100% {
      transform: scale(2.5);
      opacity: 0;
    }
  }

  .status-indicator {
    transition: transform 0.3s ease;
  }

  .discord-status-wrapper:hover .status-indicator {
    transform: scale(1.1);
  }
</style>
