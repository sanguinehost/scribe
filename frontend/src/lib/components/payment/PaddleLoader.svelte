<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';

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

			// Initialize Paddle with environment detection
			const isDevelopment = window.location.hostname === 'localhost';
			const isStaging = window.location.hostname.includes('staging');
			
			// Use sandbox for development and staging
			const environment = isDevelopment || isStaging ? 'sandbox' : 'production';
			
			if (window.Paddle) {
				window.Paddle.Initialize({
					environment,
					// Paddle will auto-detect the domain for webhook URLs
				});
			}

			paddleLoaded = true;
			console.log(`Paddle.js loaded successfully in ${environment} mode`);

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