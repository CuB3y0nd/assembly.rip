<script lang="ts">
  import { onMount } from "svelte";

  interface Player {
    isPlaying: boolean;
    songUrl?: string;
    title?: string;
    artist?: string;
  }

  let playerPromise: Promise<Player>;
  let initial = true;

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

  playerPromise = loadPlayer();

  onMount(() => {
    const id = setInterval(() => {
      initial = false;
      playerPromise = loadPlayer();
    }, 30000);

    return () => clearInterval(id);
  });
</script>

{#await playerPromise}
  {#if initial}
    <span class="now-playing">Loading...</span>
  {:else}
    <span class="loading-indicator">Refreshing...</span>
  {/if}
{:then player}
  {#if player.isPlaying}
    <a class="now-playing" href={player.songUrl}>
      {player.title} - {player.artist}
    </a>
  {:else}
    <span class="now-playing"
      >No song at the moment — enjoying the silence.</span
    >
  {/if}
{/await}
