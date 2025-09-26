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

			// Wait for window.Paddle to be available with polling mechanism
			const initializePaddle = () => {
				return new Promise<void>((resolve, reject) => {
					const checkPaddle = () => {
						if (window.Paddle && window.Paddle.Initialize) {
							try {
								// Detect environment from token prefix
								const isTestToken = PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.startsWith('test_');
								const environment = isTestToken ? 'sandbox' : 'production';

								console.log('🔧 Paddle Environment Detection:', {
									token: PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.substring(0, 8) + '...',
									isTestToken,
									environment
								});

								// CRITICAL: Set environment BEFORE Initialize for sandbox tokens
								if (isTestToken) {
									console.log('🧪 Setting Paddle environment to sandbox');
									// Define proper type for Paddle with Environment
									interface PaddleWithEnvironment {
										Initialize: (config: unknown) => void;
										Environment?: {
											set: (environment: 'sandbox' | 'production') => void;
										};
										Checkout?: unknown;
									}
									const paddleEnv = window.Paddle as PaddleWithEnvironment;
									paddleEnv.Environment?.set('sandbox');
								}

								// Detect user's theme preference
								const isDarkMode =
									window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
								const theme = isDarkMode ? 'dark' : 'light';

								// Detect user's locale (fallback to 'en')
								const locale = navigator.language?.substring(0, 2) || 'en';

								console.log('🎨 Paddle UI Configuration:', { theme, locale });

								// Initialize Paddle with proper configuration
								window.Paddle.Initialize({
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

								console.log('✅ Paddle initialized successfully in', environment, 'environment');
								resolve();
							} catch (initError) {
								console.error('❌ Paddle initialization error:', initError);
								reject(new Error(`Paddle initialization failed: ${initError}`));
							}
						} else {
							// Paddle not ready yet, try again in 100ms
							setTimeout(checkPaddle, 100);
						}
					};

					// Start checking for Paddle
					checkPaddle();

					// Add timeout to prevent infinite waiting (10 seconds)
					setTimeout(() => {
						reject(
							new Error(
								'Paddle initialization timeout: window.Paddle not available after 10 seconds'
							)
						);
					}, 10000);
				});
			};

			// Initialize Paddle and only set success flag after initialization completes
			await initializePaddle();

			paddleLoaded = true;
			console.log(
				`Paddle.js initialized successfully with token: ${PUBLIC_PADDLE_CLIENT_SIDE_TOKEN.substring(0, 8)}...`
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
