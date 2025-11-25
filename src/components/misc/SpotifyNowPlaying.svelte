<script lang="ts">
interface Player {
	isPlaying: boolean;
	songUrl?: string;
	title?: string;
	artist?: string;
}

let playerPromise: Promise<Player> = (async () => {
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
})();
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
