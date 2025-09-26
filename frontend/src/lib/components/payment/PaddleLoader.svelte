<script lang="ts">
	import { onMount } from 'svelte';
	import { browser as _browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { PUBLIC_PADDLE_CLIENT_SIDE_TOKEN } from '$env/static/public';

	let paddleLoaded = false;
	let paddleError: string | null = null;

	/**
	 * Loads Paddle.js SDK dynamically
	 * This component should be included once per app to initialize Paddle
	 */
	onMount(async () => {
		if (!_browser || !ENABLE_PAYMENTS) {
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

			// Initialize Paddle with token and checkout settings
			// Environment is auto-detected from token prefix (test_ for sandbox, live_ for production)
			if (
				(window as unknown as { Paddle?: { Initialize: (...args: unknown[]) => unknown } }).Paddle
					?.Initialize
			) {
				// Detect user's theme preference
				const isDarkMode =
					window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
				const theme = isDarkMode ? 'dark' : 'light';

				// Detect user's locale (fallback to 'en')
				const locale = navigator.language?.substring(0, 2) || 'en';

				(
					window as unknown as { Paddle?: { Initialize: (...args: unknown[]) => unknown } }
				).Paddle?.Initialize({
					token: PUBLIC_PADDLE_CLIENT_SIDE_TOKEN,
					checkout: {
						settings: {
							displayMode: 'overlay', // Default to overlay mode
							theme: theme,
							locale: locale,
							variant: 'one-page', // Use simpler one-page checkout
							allowLogout: false, // Don't allow logout in checkout
							frameStyle:
								'width: 100%; min-width: 312px; background-color: transparent; border: none;' // For inline mode if needed
						}
					},
					eventCallback: (_event: { name: string; data: unknown }) => {
						// Log Paddle events for debugging
						console.log('Paddle event:', _event.name, _event.data);
					}
				});
			}

			paddleLoaded = true;
			console.log(
				`Paddle.js loaded successfully with token: ${PUBLIC_PADDLE_CLIENT_SIDE_TOKEN.substring(0, 8)}...`
			);
		} catch (_error) {
			console.error('Failed to load Paddle.js:', _error);
			paddleError = _error instanceof Error ? _error.message : 'Unknown error loading Paddle.js';
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
