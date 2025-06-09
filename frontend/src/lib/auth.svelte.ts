import type { User } from '$lib/types';

interface AuthState {
	user: User | null;
	isAuthenticated: boolean;
	isLoading: boolean; // To track initial auth state loading
	hasConnectionError: boolean; // To track if we have connection issues
}

// Initialize the auth store with Svelte 5 runes
const auth = $state<AuthState>({
	user: null,
	isAuthenticated: false,
	isLoading: true, // Start in loading state
	hasConnectionError: false
});

// Reactive derivations - export functions instead of derived state to comply with Svelte 5 module rules
export function getCurrentUser() {
	return auth.user;
}

export function getIsAuthenticated() {
	return auth.isAuthenticated;
}

export function getIsLoadingAuth() {
	return auth.isLoading;
}

export function getHasConnectionError() {
	return auth.hasConnectionError;
}

// Functions to update the auth state
export function setAuthenticated(user: User): void {
	// Ensure backwards compatibility by mapping user_id to id if needed
	const normalizedUser: User = {
		...user,
		id: user.id || user.user_id // Use id if present, otherwise use user_id
	};

	auth.user = normalizedUser;
	auth.isAuthenticated = true;
	auth.isLoading = false;
	auth.hasConnectionError = false; // Clear any connection errors

	// Clear connection error and session expired debounce when successfully authenticated
	if (connectionErrorTimeout) {
		clearTimeout(connectionErrorTimeout);
		connectionErrorTimeout = null;
	}
	if (sessionInvalidatedTimeout) {
		clearTimeout(sessionInvalidatedTimeout);
		sessionInvalidatedTimeout = null;
	}
	hasShownConnectionError = false;
	hasShownSessionInvalidated = false;

	// User authentication logging removed for production
}

export function setUnauthenticated(clearUser: boolean = true): void {
	if (clearUser) {
		auth.user = null;
	}
	auth.isAuthenticated = false;
	auth.isLoading = false; // Finished loading, even if it's to an unauthenticated state
	auth.hasConnectionError = false; // Clear connection errors when explicitly unauthenticated
	console.log(`[${new Date().toISOString()}] auth.svelte.ts: User set to unauthenticated.`);
}

// Debounce connection error notifications to avoid spam
let connectionErrorTimeout: ReturnType<typeof setTimeout> | null = null;
let hasShownConnectionError = false;
let sessionInvalidatedTimeout: ReturnType<typeof setTimeout> | null = null;
let hasShownSessionInvalidated = false;

export function setConnectionError(): void {
	auth.hasConnectionError = true;
	auth.isLoading = false;
	console.log(`[${new Date().toISOString()}] auth.svelte.ts: Connection error detected.`);

	// Debounce the toast notification to avoid showing multiple identical toasts
	if (browser && !hasShownConnectionError) {
		hasShownConnectionError = true;
		window.dispatchEvent(new CustomEvent('auth:connection-error'));

		// Reset the flag after 10 seconds to allow new notifications if the issue persists
		connectionErrorTimeout = setTimeout(() => {
			hasShownConnectionError = false;
		}, 10000);
	}
}

export function setSessionExpired(): void {
	auth.user = null;
	auth.isAuthenticated = false;
	auth.isLoading = false;
	auth.hasConnectionError = false; // Clear connection errors - this is a session issue, not network
	console.log(`[${new Date().toISOString()}] auth.svelte.ts: Session expired, user logged out.`);

	// Debounce session expired notifications
	if (browser && !hasShownSessionInvalidated) {
		hasShownSessionInvalidated = true;
		window.dispatchEvent(new CustomEvent('auth:session-expired'));

		// Reset the flag after 5 seconds
		sessionInvalidatedTimeout = setTimeout(() => {
			hasShownSessionInvalidated = false;
		}, 5000);
	}
}

export function clearConnectionError(): void {
	auth.hasConnectionError = false;
	// Clear the debounce timeouts
	if (connectionErrorTimeout) {
		clearTimeout(connectionErrorTimeout);
		connectionErrorTimeout = null;
	}
	hasShownConnectionError = false;
	console.log(`[${new Date().toISOString()}] auth.svelte.ts: Connection error cleared.`);
}

export function setLoading(): void {
	auth.isLoading = true;
	// Loading state logging removed for production
}

// Function to initialize auth state, typically called from a root layout load function
// This function will attempt to fetch the current user from the backend.
// If successful, it updates the store. If it fails (e.g., 401), it also updates the store.
import { apiClient } from '$lib/api';
import { browser } from '$app/environment';

let initializePromise: Promise<void> | null = null;

export async function initializeAuth(): Promise<void> {
	if (!browser) {
		console.log(
			`[${new Date().toISOString()}] auth.svelte.ts: Skipping auth initialization on server.`
		);
		// Ensure loading is false if we're on the server and not actually fetching.
		// This might be set by a server load function passing initial data.
		if (auth.isLoading && !auth.user) {
			// Only if no user data was passed from server
			auth.isLoading = false;
		}
		return;
	}

	// Prevent multiple initializations
	if (initializePromise) {
		console.log(
			`[${new Date().toISOString()}] auth.svelte.ts: Auth initialization already in progress or completed.`
		);
		return initializePromise;
	}

	// Auth initialization logging removed for production
	setLoading();

	initializePromise = (async () => {
		try {
			// Attempt to get the current session/user info from the backend.
			// This relies on the browser sending the HttpOnly session cookie.
			const result = await apiClient.getUser(); // Use existing getUser method

			if (result.isOk()) {
				const user = result.value;
				if (user) {
					setAuthenticated(user);
				} else {
					// This case should ideally not happen if backend returns Ok() only with a user.
					// If backend can return Ok() with no user for a valid session but no user data, handle it.
					console.warn(
						`[${new Date().toISOString()}] auth.svelte.ts: getCurrentUser returned OK but no user object.`
					);
					setUnauthenticated();
				}
			} else {
				// ApiError, including 401 if not authenticated or network errors
				console.log(
					`[${new Date().toISOString()}] auth.svelte.ts: Failed to get current user. Error:`,
					result.error
				);

				// For network errors, be less aggressive - just set loading to false but don't clear user completely
				// Let the user see the error message and decide what to do
				if (result.error.name === 'ApiNetworkError') {
					console.log(
						`[${new Date().toISOString()}] auth.svelte.ts: Network error during auth check - server may be down. Keeping current state.`
					);
					setConnectionError(); // Set connection error state, but keep user data
				} else if (result.error.name === 'ApiResponseError' && result.error.statusCode === 401) {
					// Session expired - clear user and show specific message
					console.log(
						`[${new Date().toISOString()}] auth.svelte.ts: Session expired (401). Logging out user.`
					);
					setSessionExpired();
				} else {
					// For other API errors, treat as unauthenticated
					setUnauthenticated();
				}
			}
		} catch (error) {
			console.error(
				`[${new Date().toISOString()}] auth.svelte.ts: Unexpected error during auth initialization:`,
				error
			);
			setUnauthenticated(); // Ensure unauthenticated state on unexpected errors
		}
	})();

	return initializePromise;
}

// Optional: Expose the raw state for direct manipulation if absolutely necessary,
// though using the exported functions (setAuthenticated, setUnauthenticated) is preferred.
// export const _authStore = auth;

// Auth store initialization logging removed for production
