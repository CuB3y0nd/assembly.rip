<script lang="ts">
import { inject } from "@vercel/analytics";
import { onMount } from "svelte";

onMount(() => {
	if (!window.__vercelAnalyticsInjected) {
		inject();
		window.__vercelAnalyticsInjected = true;
	}
});
</script>
