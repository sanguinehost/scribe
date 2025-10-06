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
		setAuthenticated,
		setUnauthenticated,
		getIsAuthenticated
	} from '$lib/auth.svelte'; // Import from new auth store
	import { goto as _goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import type { User } from '$lib/types';
	import ReAuthModal from '$lib/components/ReAuthModal.svelte';

	let { data, children } = $props<{ data: { user?: User | null }; children: unknown }>();

	// Re-authentication modal state
	let showReAuthModal = $state(false);
	let reAuthReason = $state<'dek_missing' | 'session_expired'>('dek_missing');
	let reAuthModalShownOnce = $state(false); // Prevent duplicate modals

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

	// Initialize new auth store with server data if available, then run client-side initialization.
	// This $effect runs when `data.user` changes or on component initialization.
	$effect(() => {
		if (data.user) {
			setAuthenticated(data.user);
		}
		// User data logging removed to prevent sensitive information exposure
	});

	onMount(() => {
		// Initialize auth asynchronously without blocking mount
		(async () => {
			// initializeAuth will attempt to fetch the user if not already set by server data,
			// or if we want to re-verify on client-side navigation to a page with this layout.
			// It's designed to be safe to call even if already authenticated.
			await initializeAuth();

			// Initialize subscription store after auth is ready and payments are enabled
			if (ENABLE_PAYMENTS && getIsAuthenticated()) {
				subscriptionStore.initialize();
			}
			// Initialization logging removed for production
		})();

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
		{@render children()}
	</TooltipProvider>
</ThemeProvider>
