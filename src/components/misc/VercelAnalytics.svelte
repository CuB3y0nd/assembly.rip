<script lang="ts">
  import { onMount } from "svelte";
  import { inject } from "@vercel/analytics";

  onMount(() => {
    if (!window.__vercelAnalyticsInjected) {
      inject();
      window.__vercelAnalyticsInjected = true;
    }
  });
</script>
