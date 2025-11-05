<script lang="ts">
	import '../app.css';
	import { ThemeProvider } from '@sejohnson/svelte-themes';
	import { Toaster } from '$lib/components/ui/sonner';
	import { TooltipProvider } from '$lib/components/ui/tooltip';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { ENABLE_LOCAL_LLM, ENABLE_PAYMENTS } from '$lib/utils/features';
	import { PaddleLoader } from '$lib/components/payment';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import {
		initializeAuth,
		setUnauthenticated,
		getIsAuthenticated,
		setAuthReady
	} from '$lib/auth.svelte'; // Import from new auth store
	import { goto as _goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import type { User } from '$lib/types';
	import ReAuthModal from '$lib/components/ReAuthModal.svelte';

	let { children } = $props<{ data?: { user?: User | null }; children: unknown }>();

	// Public routes that don't require authentication
	const publicRoutes = ['/welcome', '/signin', '/signup', '/pricing', '/verify-email'];
	const isPublicRoute = $derived(publicRoutes.includes($page.url.pathname));

	// Re-authentication modal state
	let showReAuthModal = $state(false);
	let reAuthReason = $state<'dek_missing' | 'session_expired'>('dek_missing');
	let reAuthModalShownOnce = $state(false); // Prevent duplicate modals

	// CRITICAL FIX: Simple boolean flag for app ready state
	// This creates a clear reactive dependency that Svelte 5 can track
	// (getter functions in conditionals don't create subscriptions when condition is initially false)
	let isAppReady = $state(false);

	// Initialize settings store
	const settingsStore = new SettingsStore();
	SettingsStore.toContext(settingsStore);

	// Initialize LLM store for local model management (conditionally)
	if (ENABLE_LOCAL_LLM) {
		// Initialize the global singleton store immediately without context
		import('$lib/stores/llm.svelte')
			.then(({ initGlobalLlmStore }) => {
				try {
					initGlobalLlmStore();
				} catch (_error) {
					console.warn('LlmStore initialization failed:', _error);
				}
			})
			.catch((error) => {
				console.warn('LlmStore module load failed:', error);
			});

		// Initialize model lifecycle store for local model management
		import('$lib/stores/modelLifecycle.svelte')
			.then(({ initGlobalModelLifecycleStore }) => {
				try {
					initGlobalModelLifecycleStore();
				} catch (_error) {
					console.warn('ModelLifecycleStore initialization failed:', _error);
				}
			})
			.catch((error) => {
				console.warn('ModelLifecycleStore module load failed:', error);
			});
	}

	onMount(() => {
		console.log('[STEP 1] onMount started');

		// Run async initialization in IIFE
		(async () => {
			// TEMPORARILY DISABLED - Testing if logger init causes the freeze
			// if (import.meta.env.PUBLIC_ENVIRONMENT === 'desktop') {
			// 	console.log('[STEP 1.5] Initializing desktop logger...');
			// 	try {
			// 		const { initDesktopLogger } = await import('$lib/utils/desktop-logger');
			// 		const success = await initDesktopLogger();
			// 		if (success) {
			// 			console.log('[STEP 1.6] Desktop logger initialized - all logs now forwarded to backend');
			// 		} else {
			// 			console.warn('[STEP 1.6] Desktop logger failed - using native console only');
			// 		}
			// 	} catch (e) {
			// 		console.error('[STEP 1.6] Failed to init desktop logger:', e);
			// 	}
			// }
			console.log(
				'[STEP 1.5] Logger init DISABLED for testing - checking if this was causing freeze'
			);

			// Helper function to hide the loading overlay from app.html
			const hideLoadingOverlay = () => {
				console.log('[+layout.svelte] Hiding loading overlay');
				const overlay = document.getElementById('loading-overlay');
				if (overlay) {
					overlay.classList.add('hidden');
					// Remove from DOM after transition completes
					setTimeout(() => overlay.remove(), 600);
				}
			};

			// CRITICAL: Failsafe to ALWAYS hide overlay after 5 seconds, no matter what
			const failsafeTimeout = setTimeout(() => {
				console.error('[+layout.svelte] Failsafe triggered - hiding overlay after timeout');
				hideLoadingOverlay();
			}, 5000);

			// Helper to add timeout to any promise
			const withTimeout = <T,>(
				promise: Promise<T>,
				timeoutMs: number,
				operation: string
			): Promise<T> => {
				return Promise.race([
					promise,
					new Promise<T>((_, reject) =>
						setTimeout(
							() => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)),
							timeoutMs
						)
					)
				]);
			};

			// NOTE: Tauri log API attempts removed - was causing hangs and not working properly
			// All logging now goes to console.log which is captured by backend in desktop mode
			// Variable kept for potential future use
			let _tauriLog: unknown = null;

			// CRITICAL FIX: Wrap entire initialization IIFE with hard timeout at Promise level
			// This catches Rust-level hangs that prevent JS setTimeout from firing
			console.log('[STEP 4] Starting main initialization with hard timeout wrapper');
			const initPromise = (async () => {
				try {
					console.log('[STEP 5] Importing isDesktopMode...');
					const { isDesktopMode } = await import('$lib/utils/features');
					console.log('[STEP 6] isDesktopMode imported');

					console.log('[STEP 7] Importing apiClient...');
					const { apiClient } = await import('$lib/api');
					console.log('[STEP 8] apiClient imported');

					const log = async (msg: string) => {
						console.log(msg);
					};
					const logError = async (msg: string) => {
						console.error(msg);
					};

					if (isDesktopMode()) {
						log('[STEP 9] Desktop mode detected, initializing...');

						// CRITICAL: Backend health check BEFORE making any API calls
						// If backend/protocol handler isn't ready, fail fast instead of hanging
						log('[STEP 10] Checking backend health...');
						try {
							const healthCheckStart = Date.now();
							const healthResult = await withTimeout(
								fetch('scribe://localhost/api/health', { method: 'GET' }),
								2000,
								'Backend health check'
							);
							const healthCheckDuration = Date.now() - healthCheckStart;
							if (healthResult.ok) {
								log(`[STEP 11] ✓ Backend health check passed (${healthCheckDuration}ms)`);
							} else {
								logError(`[STEP 11] ✗ Backend health check failed: ${healthResult.status}`);
								throw new Error(`Backend health check failed with status ${healthResult.status}`);
							}
						} catch (healthError) {
							logError(`[STEP 11] ✗ Backend health check error: ${healthError}`);
							setUnauthenticated();
							isAppReady = true; // CRITICAL: Set flag so error states can render
							hideLoadingOverlay();
							// Show error to user
							console.error(
								'[+layout.svelte] Backend is not responding. Please restart the application.'
							);
							alert('Backend is not responding. Please restart the application.');
							return;
						}

						// Get desktop config
						log('[STEP 12] Getting desktop config...');
						const configResult = await apiClient.getDesktopConfig();
						log('[STEP 13] Desktop config request completed');

						if (configResult.isOk()) {
							const config = configResult.value;
							log(`[STEP 14] Desktop config loaded: ${JSON.stringify(config)}`);

							// Redirect to welcome if setup not complete
							if (!config.setup_complete && window.location.pathname !== '/welcome') {
								log('[STEP 15] Setup not complete, redirecting to /welcome');
								isAppReady = true; // CRITICAL: Set flag so /welcome page can render
								hideLoadingOverlay();
								_goto('/welcome');
								return;
							}

							// Auto-login for Quick Start mode
							if (config.setup_complete && config.auth_mode === 'quick_start') {
								log('[STEP 16] Quick Start mode, attempting auto-login...');

								const autoLoginResult = await apiClient.desktopAutoLogin();
								log('[STEP 17] Auto-login request completed');

								if (autoLoginResult.isOk()) {
									const tokenData = autoLoginResult.value;
									log('[STEP 18] ✓ Auto-login successful');

									// Save tokens to Tauri secure storage
									try {
										log('[STEP 19] Importing Tauri invoke...');
										const { invoke } = await import('@tauri-apps/api/core');
										log('[STEP 20] Saving tokens to secure storage...');
										await invoke('save_tokens', {
											accessToken: tokenData.access_token,
											refreshToken: tokenData.refresh_token
										});
										log('[STEP 21] ✓ JWT tokens saved');

										// Save DEK if present (Quick Start mode)
										if (tokenData.dek) {
											log('[STEP 22] Saving DEK to secure storage...');
											await invoke('save_local_dek', { dek: tokenData.dek });
											log('[STEP 23] ✓ DEK saved to secure storage');
										}
										// CRITICAL: Reload tokens/DEK into desktopAuth in-memory cache
										// This ensures subsequent API calls have authentication headers
										log('[STEP 24] Reloading credentials into memory...');
										await withTimeout(
											apiClient.reinitializeDesktopAuth(),
											5000,
											'Reinitialize desktop auth'
										);
										log('[STEP 25] ✓ Credentials reloaded into memory');

										// Now initialize auth to populate auth store with user data
										// Add explicit timeout to prevent UI freeze if backend is slow/offline
										log('[STEP 26] Initializing auth store (fetching user data)...');
										try {
											await withTimeout(initializeAuth(true), 8000, 'Initialize auth');
											log('[STEP 27] ✓ Auth initialization successful');
											// CRITICAL: Set auth ready flag BEFORE hiding overlay
											// This signals child components that auth is complete and tokens are loaded
											setAuthReady(true);
											log('[STEP 27a] ✓ Auth ready flag set - safe to render child components');
										} catch (authError) {
											logError(`[STEP 27] ✗ Auth initialization failed or timed out: ${authError}`);
											// Auth init failed but we have tokens saved - app can still work
											// Set unauthenticated state so app doesn't hang waiting for user data
											setUnauthenticated();
											setAuthReady(false); // Auth not ready if initialization failed
										}

										// Initialize subscription store after auth is ready
										if (ENABLE_PAYMENTS && getIsAuthenticated()) {
											log('[STEP 28] Initializing subscription store...');
											try {
												subscriptionStore.initialize();
												log('[STEP 29] ✓ Subscription store initialized');
											} catch (subError) {
												logError(`[STEP 29] ✗ Subscription store init failed: ${subError}`);
												// Non-fatal - app can continue without subscription data
											}
										}

										// Hide loading overlay - auth is complete
										log('[STEP 30] ✓ Auth complete (Quick Start auto-login)');
										isAppReady = true; // CRITICAL: Set flag to trigger reactive re-render
										log('[STEP 30a] ✓ App ready flag set - UI will now show');
										hideLoadingOverlay();
									} catch (saveError) {
										logError(`[STEP 31] ✗ Failed during token save/auth: ${saveError}`);
										// Token save or auth initialization failed - redirect to welcome to retry setup
										isAppReady = true; // CRITICAL: Set flag so /welcome page can render
										hideLoadingOverlay();
										_goto('/welcome');
									}
								} else {
									logError(`[STEP 32] ✗ Auto-login failed: ${autoLoginResult.error}`);
									// Auto-login failed - redirect to welcome to retry setup
									isAppReady = true; // CRITICAL: Set flag so /welcome page can render
									hideLoadingOverlay();
									_goto('/welcome');
								}
							} else {
								// For non-Quick-Start modes, run normal auth init
								log('[+layout.svelte] Non-Quick-Start mode, running normal auth init');
								try {
									await withTimeout(initializeAuth(), 8000, 'Initialize auth (non-Quick-Start)');
									log('[+layout.svelte] Auth initialization successful');
									setAuthReady(true);
									log('[+layout.svelte] Auth ready flag set - safe to render child components');
								} catch (authError) {
									logError(
										`[+layout.svelte] Auth initialization failed or timed out: ${authError}`
									);
									setUnauthenticated();
									setAuthReady(false);
								}

								if (ENABLE_PAYMENTS && getIsAuthenticated()) {
									try {
										subscriptionStore.initialize();
									} catch (subError) {
										logError(`[+layout.svelte] Subscription store init failed: ${subError}`);
									}
								}

								// Hide loading overlay
								log('[+layout.svelte] Auth init complete (non-Quick-Start desktop)');
								isAppReady = true; // CRITICAL: Set flag to trigger reactive re-render
								log('[+layout.svelte] App ready flag set - UI will now show');
								hideLoadingOverlay();
							}
						} else {
							logError(`[+layout.svelte] Failed to get desktop config: ${configResult.error}`);
							// Config load failed - redirect to welcome
							isAppReady = true; // CRITICAL: Set flag so /welcome page can render
							hideLoadingOverlay();
							_goto('/welcome');
						}
					} else {
						// Non-desktop mode (web/cloud) - run normal auth init
						log('[+layout.svelte] Web/cloud mode, running normal auth init');
						try {
							await withTimeout(initializeAuth(), 8000, 'Initialize auth (web/cloud)');
							log('[+layout.svelte] Auth initialization successful');
							setAuthReady(true);
							log('[+layout.svelte] Auth ready flag set - safe to render child components');
						} catch (authError) {
							logError(`[+layout.svelte] Auth initialization failed or timed out: ${authError}`);
							setUnauthenticated();
							setAuthReady(false);
						}

						if (ENABLE_PAYMENTS && getIsAuthenticated()) {
							try {
								subscriptionStore.initialize();
							} catch (subError) {
								logError(`[+layout.svelte] Subscription store init failed: ${subError}`);
							}
						}

						// Hide loading overlay
						log('[+layout.svelte] Auth init complete (web/cloud mode)');
						isAppReady = true; // CRITICAL: Set flag to trigger reactive re-render
						log('[+layout.svelte] App ready flag set - UI will now show');
						hideLoadingOverlay();
					}
				} catch (error) {
					console.error(`[CRITICAL ERROR] Initialization error at unknown step: ${error}`);
					console.error('[+layout.svelte] Fatal initialization error:', error);
					// Force auth to non-loading state so app becomes usable even if init fails
					setUnauthenticated();
					isAppReady = true; // CRITICAL: Set flag so error states can render
				} finally {
					// CRITICAL: Always hide overlay and clear failsafe, even if initialization fails
					console.log('[FINALLY] Cleaning up initialization');
					clearTimeout(failsafeTimeout);
					hideLoadingOverlay();
				}
			})();

			// CRITICAL FIX: Hard timeout wrapper at Promise level
			// If initPromise doesn't resolve in 8 seconds, force cleanup and show error
			// This catches Rust-level hangs that prevent JS event loop from processing
			Promise.race([
				initPromise,
				new Promise((_, reject) =>
					setTimeout(() => reject(new Error('Initialization IIFE timed out after 8 seconds')), 8000)
				)
			]).catch((error) => {
				console.error('[TIMEOUT] Initialization IIFE did not complete:', error);
				console.error('[TIMEOUT] Forcing overlay hide and showing error to user');
				clearTimeout(failsafeTimeout);
				hideLoadingOverlay();
				setUnauthenticated();
				isAppReady = true; // CRITICAL: Set flag so error states can render
				// Show error to user
				alert(
					'Application initialization timed out. Please restart the application. If this problem persists, check the logs.'
				);
			});
		})(); // End async IIFE

		// Set up global listener for auth:invalidated events (for any legacy components)
		const handleAuthInvalidated = () => {
			console.log(
				'[Layout] Global auth:invalidated event received (legacy), redirecting to signin'
			);
			setUnauthenticated();

			// Clear subscription data when auth is invalidated
			if (ENABLE_PAYMENTS) {
				subscriptionStore.clearData();
			}

			_goto('/signin');
		};

		window.addEventListener('auth:invalidated', handleAuthInvalidated);

		// Set up listener for connection errors to show user-friendly notifications
		const handleConnectionError = () => {
			toast.warning('Connection to server lost', {
				description: 'Some features may not work properly. Please check your internet connection.',
				duration: 5000
			});
		};

		// Set up listener for session expiry to show specific message and redirect
		const handleSessionExpired = () => {
			toast.error('Session expired', {
				description: 'Please sign in again to continue.',
				duration: 8000
			});
			// Redirect to signin after a brief delay
			setTimeout(() => {
				_goto('/signin');
			}, 1000);
		};

		// Set up listener for connection restored to show positive feedback
		const handleConnectionRestored = () => {
			toast.success('Connection restored', {
				description: 'Server is back online. You can continue using the app.',
				duration: 3000
			});
			// Force session revalidation now that connection is restored
			initializeAuth(true);

			// Retry LLM store check after connection is restored
			if (ENABLE_LOCAL_LLM) {
				import('$lib/stores/llm.svelte')
					.then(({ getGlobalLlmStore }) => {
						const store = getGlobalLlmStore();
						if (store) {
							store.retryAfterAuth();
						}
					})
					.catch((e) => {
						console.warn('Failed to retry LlmStore after connection restored:', e);
					});
			}
		};

		// Set up listener for authentication success to retry LLM store
		const handleAuthSuccess = () => {
			console.log('Authentication successful, retrying LlmStore...');
			if (ENABLE_LOCAL_LLM) {
				import('$lib/stores/llm.svelte')
					.then(({ getGlobalLlmStore }) => {
						const store = getGlobalLlmStore();
						if (store) {
							store.retryAfterAuth();
						}
					})
					.catch((e) => {
						console.warn('Failed to retry LlmStore after auth success:', e);
					});
			}

			// Initialize subscription store when authentication succeeds
			if (ENABLE_PAYMENTS) {
				subscriptionStore.initialize();
			}
		};

		// Set up listener for DEK missing to show re-authentication modal
		const handleDekMissing = (event: Event) => {
			const customEvent = event as CustomEvent<{
				reason: 'dek_missing' | 'session_expired';
				immediate?: boolean;
				endpoint?: string;
			}>;

			// Prevent showing modal multiple times (can happen if multiple API calls fail simultaneously)
			if (reAuthModalShownOnce && showReAuthModal) {
				console.log(
					'[Layout] DEK missing detected but modal already shown, ignoring duplicate event'
				);
				return;
			}

			console.log('[Layout] DEK missing detected, showing re-authentication modal', {
				immediate: customEvent.detail?.immediate,
				endpoint: customEvent.detail?.endpoint
			});
			reAuthReason = customEvent.detail?.reason || 'dek_missing';
			showReAuthModal = true;
			reAuthModalShownOnce = true;
		};

		window.addEventListener('auth:connection-error', handleConnectionError);
		window.addEventListener('auth:session-expired', handleSessionExpired);
		window.addEventListener('auth:connection-restored', handleConnectionRestored);
		window.addEventListener('auth:success', handleAuthSuccess);
		window.addEventListener('auth:dek-missing', handleDekMissing);

		// Set up periodic auth check to detect session expiry during active use
		// Reduced from 5 minutes to 2 minutes for faster detection of invalidated sessions
		const periodicAuthCheck = setInterval(
			() => {
				// Only check if user thinks they're authenticated
				if (getIsAuthenticated()) {
					initializeAuth(true); // Force recheck to bypass cached promise
				}
			},
			2 * 60 * 1000
		); // Check every 2 minutes

		// Set up visibility change listener to check session when user returns to tab
		// This handles cases where backend is redeployed while user is away
		const handleVisibilityChange = () => {
			if (document.visibilityState === 'visible' && getIsAuthenticated()) {
				console.log('[Layout] Tab became visible, validating session...');
				initializeAuth(true); // Force recheck when user returns to tab
			}
		};

		document.addEventListener('visibilitychange', handleVisibilityChange);

		// Cleanup
		return () => {
			window.removeEventListener('auth:invalidated', handleAuthInvalidated);
			window.removeEventListener('auth:connection-error', handleConnectionError);
			window.removeEventListener('auth:session-expired', handleSessionExpired);
			window.removeEventListener('auth:connection-restored', handleConnectionRestored);
			window.removeEventListener('auth:success', handleAuthSuccess);
			window.removeEventListener('auth:dek-missing', handleDekMissing);
			document.removeEventListener('visibilitychange', handleVisibilityChange);
			clearInterval(periodicAuthCheck);
		};
	});

	// Handler for successful re-authentication
	function handleReAuthSuccess() {
		console.log('[Layout] Re-authentication successful, reinitializing auth');
		// Force auth reinitialization to populate DEK from fresh login
		initializeAuth(true);

		// Show success notification
		toast.success('Authentication successful', {
			description: 'Your encryption key has been restored. You can continue using the app.',
			duration: 3000
		});

		// Dispatch event to trigger data refresh in sidebar components
		console.log('[Layout] Dispatching auth:reauth-complete event for sidebar refresh');
		window.dispatchEvent(new CustomEvent('auth:reauth-complete'));
	}
</script>

<ThemeProvider attribute="class" disableTransitionOnChange>
	<TooltipProvider>
		<Toaster position="top-center" />
		{#if ENABLE_PAYMENTS}
			<PaddleLoader />
		{/if}
		<ReAuthModal
			bind:open={showReAuthModal}
			reason={reAuthReason}
			onSuccess={handleReAuthSuccess}
		/>
		{#if isAppReady || isPublicRoute}
			{@render children()}
		{:else}
			<div class="flex h-screen items-center justify-center">
				<div class="loading-content">
					<svg class="loading-logo" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
						<circle
							cx="50"
							cy="50"
							r="40"
							fill="none"
							stroke="currentColor"
							stroke-width="4"
							opacity="0.2"
						/>
						<path
							d="M50 10 A40 40 0 0 1 50 90"
							fill="none"
							stroke="currentColor"
							stroke-width="4"
							stroke-linecap="round"
						>
							<animateTransform
								attributeName="transform"
								type="rotate"
								from="0 50 50"
								to="360 50 50"
								dur="1s"
								repeatCount="indefinite"
							/>
						</path>
					</svg>
					<div class="loading-text">Initializing...</div>
				</div>
			</div>
		{/if}
	</TooltipProvider>
</ThemeProvider>
