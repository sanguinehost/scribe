<script lang="ts">
	import '../app.css';
	import { ThemeProvider } from '@sejohnson/svelte-themes';
	import { Toaster } from '$lib/components/ui/sonner';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { ENABLE_LOCAL_LLM } from '$lib/utils/features';
	import {
		initializeAuth,
		setAuthenticated,
		setUnauthenticated,
		getIsAuthenticated
	} from '$lib/auth.svelte'; // Import from new auth store
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import type { User } from '$lib/types';

	let { data, children } = $props<{ data: { user?: User | null }; children: unknown }>();

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
				} catch (error) {
					console.warn('LlmStore initialization failed:', error);
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
				} catch (error) {
					console.warn('ModelLifecycleStore initialization failed:', error);
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
			// Initialization logging removed for production
		})();

		// Set up global listener for auth:invalidated events (for any legacy components)
		const handleAuthInvalidated = () => {
			console.log(
				'[Layout] Global auth:invalidated event received (legacy), redirecting to signin'
			);
			setUnauthenticated();
			goto('/signin');
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
				goto('/signin');
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
		};

		window.addEventListener('auth:connection-error', handleConnectionError);
		window.addEventListener('auth:session-expired', handleSessionExpired);
		window.addEventListener('auth:connection-restored', handleConnectionRestored);
		window.addEventListener('auth:success', handleAuthSuccess);

		// Set up periodic auth check to detect session expiry during active use
		const periodicAuthCheck = setInterval(
			() => {
				// Only check if user thinks they're authenticated
				if (getIsAuthenticated()) {
					initializeAuth(true); // Force recheck to bypass cached promise
				}
			},
			5 * 60 * 1000
		); // Check every 5 minutes

		// Cleanup
		return () => {
			window.removeEventListener('auth:invalidated', handleAuthInvalidated);
			window.removeEventListener('auth:connection-error', handleConnectionError);
			window.removeEventListener('auth:session-expired', handleSessionExpired);
			window.removeEventListener('auth:connection-restored', handleConnectionRestored);
			window.removeEventListener('auth:success', handleAuthSuccess);
			clearInterval(periodicAuthCheck);
		};
	});
</script>

<ThemeProvider attribute="class" disableTransitionOnChange>
	<Toaster position="top-center" />
	{@render children()}
</ThemeProvider>
