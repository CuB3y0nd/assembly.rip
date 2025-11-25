<script lang="ts">
  interface Player {
    isPlaying: boolean;
    songUrl?: string;
    title?: string;
    artist?: string;
  }

  let player: Player = { isPlaying: false };

  async function load() {
    try {
      const resp = await fetch("/api/spotify.json", {
        method: "GET",
        cache: "no-store",
      });
      if (!resp.ok) throw new Error("Fetch failed");
      player = await resp.json();
    } catch {
      player = { isPlaying: false };
    }
  }

  load();
</script>

{#if player.isPlaying}
  <a class="now-playing" href={player.songUrl}>
    {player.title} - {player.artist}
  </a>
{/if}
