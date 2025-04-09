<script lang="ts">
	import { onMount } from 'svelte';

	let healthStatus: string = 'Checking...';
	let error: string | null = null;

	onMount(async () => {
		try {
			// Note: In SvelteKit, relative paths like '/api/health' are automatically
			// proxied to the backend during development (if configured in vite.config.ts)
			// or should point to the deployed backend URL in production.
			// We assume the default proxy setup or the backend is accessible at this path.
			const response = await fetch('/api/health');

			if (!response.ok) {
				throw new Error(`HTTP error! status: ${response.status}`);
			}

			const data = await response.json();

			if (data && data.status) {
				healthStatus = data.status;
			} else {
				throw new Error('Invalid response format from health check');
			}
			error = null; // Clear previous errors
		} catch (e: any) {
			console.error('Failed to fetch health status:', e);
			healthStatus = 'Error';
			error = e.message || 'Unknown error fetching health status.';
		}
	});
</script>

<h1>Scribe Frontend</h1>
<p>Backend Health Status: <strong>{healthStatus}</strong></p>

{#if error}
	<p style="color: red;">Error details: {error}</p>
{/if}

<p>Visit <a href="https://svelte.dev/docs/kit">svelte.dev/docs/kit</a> to read the SvelteKit documentation.</p>
