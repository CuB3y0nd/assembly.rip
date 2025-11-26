<script lang="ts">
  import { onMount } from "svelte";

  interface Player {
    isPlaying: boolean;
    songUrl?: string;
    title?: string;
    artist?: string;
  }

  async function loadPlayer(): Promise<Player> {
    try {
      const resp = await fetch("/api/spotify.json");
      if (!resp.ok) throw new Error("Fetch failed");
      const spotifyResponse = await resp.json();
      return {
        isPlaying: spotifyResponse.isPlaying,
        songUrl: spotifyResponse.songUrl,
        title: spotifyResponse.title,
        artist: spotifyResponse.artist,
      };
    } catch {
      return { isPlaying: false };
    }
  }

  let playerPromise: Promise<Player> = loadPlayer();

  onMount(() => {
    // refresh every 30s
    const id = setInterval(() => {
      playerPromise = loadPlayer();
    }, 30000);

    return () => clearInterval(id);
  });
</script>

{#await playerPromise then player}
  {#if player.isPlaying}
    <a class="now-playing" href={player.songUrl}>
      {player.title} - {player.artist}
    </a>
  {:else}
    <span class="now-playing">Not playing anything right now.</span>
  {/if}
{/await}
