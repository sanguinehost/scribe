<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { PUBLIC_PADDLE_CLIENT_SIDE_TOKEN } from '$env/static/public';

	let paddleLoaded = false;
	let paddleError: string | null = null;

	/**
	 * Loads Paddle.js SDK dynamically
	 * This component should be included once per app to initialize Paddle
	 */
	onMount(async () => {
		if (!browser || !ENABLE_PAYMENTS) {
			return;
		}

		// Check if we have the required token
		if (!PUBLIC_PADDLE_CLIENT_SIDE_TOKEN) {
			paddleError = 'Paddle client-side token not configured';
			console.error('PUBLIC_PADDLE_CLIENT_SIDE_TOKEN environment variable is required');
			return;
		}

		try {
			// Check if Paddle is already loaded
			if (window.Paddle) {
				paddleLoaded = true;
				return;
			}

			// Create script element for Paddle.js
			const script = document.createElement('script');
			script.src = 'https://cdn.paddle.com/paddle/v2/paddle.js';
			script.async = true;

			// Wait for script to load
			await new Promise((resolve, reject) => {
				script.onload = resolve;
				script.onerror = () => reject(new Error('Failed to load Paddle.js'));
				document.head.appendChild(script);
			});

			// Initialize Paddle with token (environment is auto-detected from token prefix)
			if (window.Paddle?.Initialize) {
				window.Paddle.Initialize({
					token: PUBLIC_PADDLE_CLIENT_SIDE_TOKEN,
				});
			}

			paddleLoaded = true;
			console.log(`Paddle.js loaded successfully with token: ${PUBLIC_PADDLE_CLIENT_SIDE_TOKEN.substring(0, 8)}...`);

		} catch (error) {
			console.error('Failed to load Paddle.js:', error);
			paddleError = error instanceof Error ? error.message : 'Unknown error loading Paddle.js';
		}
	});

	// Export paddle status for other components to use
	export { paddleLoaded, paddleError };
</script>

<!-- This component doesn't render anything visible -->
{#if paddleError}
	<div class="paddle-error" style="display: none;">
		<!-- Error logged to console, no UI shown -->
	</div>
{/if}

<style>
	.paddle-error {
		display: none;
	}
</style>