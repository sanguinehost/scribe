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

// Comprehensive logout function that clears both state and cookies
let isLoggingOut = false; // Prevent duplicate logout attempts
let lastLogoutTime = 0;
const LOGOUT_DEBOUNCE = 1000; // 1 second debounce between logout attempts

export async function performLogout(
	reason: 'expired' | 'manual' | 'error' = 'manual',
	showNotification = true
): Promise<void> {
	const now = Date.now();

	// Debounce rapid logout attempts
	if (isLoggingOut || now - lastLogoutTime < LOGOUT_DEBOUNCE) {
		console.log(
			`[${new Date().toISOString()}] auth.svelte.ts: Logout already in progress or debounced, skipping duplicate attempt`
		);
		return;
	}

	lastLogoutTime = now;

	isLoggingOut = true;
	console.log(`[${new Date().toISOString()}] auth.svelte.ts: Performing logout, reason: ${reason}`);

	try {
		// Clear client-side auth state
		auth.user = null;
		auth.isAuthenticated = false;
		auth.isLoading = false;
		auth.hasConnectionError = false;

		// Clear cookies with priority on client-side (immediate) then server-side (HttpOnly backup)
		if (browser) {
			// 1. IMMEDIATE: Clear cookies client-side first (works for non-HttpOnly cookies)
			clearSessionCookies();

			// 2. BACKUP: Call server-side endpoint to clear HttpOnly cookies
			// Don't await this to avoid blocking the logout process
			fetch('/api/invalidate-session', {
				method: 'POST',
				credentials: 'include'
			})
				.then(() => {
					console.log(
						`[${new Date().toISOString()}] auth.svelte.ts: Server-side session invalidation successful`
					);
				})
				.catch((error) => {
					console.warn(
						`[${new Date().toISOString()}] auth.svelte.ts: Server-side session invalidation failed:`,
						error
					);
				});
		}

		// Clear debounce timeouts
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

		// Show notification and handle events based on reason
		if (browser && showNotification) {
			if (reason === 'expired' && !hasShownSessionInvalidated) {
				hasShownSessionInvalidated = true;
				console.log(
					`[${new Date().toISOString()}] auth.svelte.ts: Dispatching auth:session-expired event`
				);
				window.dispatchEvent(new CustomEvent('auth:session-expired'));

				// Also redirect immediately as a fallback
				setTimeout(() => {
					import('$app/navigation').then(({ goto }) => {
						console.log(
							`[${new Date().toISOString()}] auth.svelte.ts: Fallback redirect to /signin`
						);
						goto('/signin');
					});
				}, 2000); // 2 second fallback redirect

				// Reset the flag after 5 seconds
				sessionInvalidatedTimeout = setTimeout(() => {
					hasShownSessionInvalidated = false;
				}, 5000);
			} else if (reason === 'manual') {
				// For manual logout, we don't need to show a notification
				// as the user initiated the action
			}
		}

		console.log(`[${new Date().toISOString()}] auth.svelte.ts: Logout completed successfully`);
	} finally {
		isLoggingOut = false;
	}
}

export function setSessionExpired(): void {
	console.log(`[${new Date().toISOString()}] auth.svelte.ts: Session expired detected`);
	performLogout('expired', true);
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

// Enhanced client-side cookie clearing utility that works in both local and cloud environments
function clearSessionCookies(): void {
	if (!browser) return;

	try {
		// Get current domain info for more targeted deletion
		const hostname = window.location.hostname;
		const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';
		const domainParts = hostname.split('.');
		const parentDomain = domainParts.length > 2 ? '.' + domainParts.slice(-2).join('.') : '';

		// Clear all possible session cookie variations to handle different environments
		const cookieNames = ['id', 'session', 'sessionid', 'session_id'];
		const cookieOptions = [];

		for (const name of cookieNames) {
			// Basic deletion (most important - this should work for most cases)
			cookieOptions.push(`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`);
			cookieOptions.push(`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0`);

			// For localhost/development
			if (isLocalhost) {
				cookieOptions.push(
					`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=${hostname}`
				);
				cookieOptions.push(
					`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0; domain=${hostname}`
				);
			}

			// For cloud deployment with current domain
			if (!isLocalhost) {
				cookieOptions.push(
					`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=${hostname}`
				);
				cookieOptions.push(
					`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0; domain=${hostname}`
				);

				// With parent domain for subdomains
				if (parentDomain) {
					cookieOptions.push(
						`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; domain=${parentDomain}`
					);
					cookieOptions.push(
						`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0; domain=${parentDomain}`
					);
				}
			}

			// Secure variants for HTTPS environments
			if (window.location.protocol === 'https:') {
				cookieOptions.push(
					`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; secure; samesite=lax`
				);
				cookieOptions.push(
					`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0; secure; samesite=lax`
				);

				if (!isLocalhost && parentDomain) {
					cookieOptions.push(
						`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; secure; samesite=lax; domain=${parentDomain}`
					);
					cookieOptions.push(
						`${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0; secure; samesite=lax; domain=${parentDomain}`
					);
				}
			}
		}

		// Apply all cookie deletion attempts
		let successCount = 0;
		cookieOptions.forEach((cookieString) => {
			try {
				document.cookie = cookieString;
				successCount++;
			} catch (e) {
				// Silently continue if any specific cookie deletion fails
			}
		});

		console.log(
			`[${new Date().toISOString()}] auth.svelte.ts: Session cookies cleared from client-side (${successCount}/${cookieOptions.length} attempts successful)`
		);
	} catch (error) {
		console.warn(`[${new Date().toISOString()}] auth.svelte.ts: Error clearing cookies:`, error);
	}
}

// Debug utility to check current cookies (for testing cookie deletion)
export function debugCookies(): void {
	if (!browser) return;

	const allCookies = document.cookie;
	const sessionCookies = allCookies
		.split(';')
		.map((cookie) => cookie.trim())
		.filter(
			(cookie) =>
				cookie.startsWith('id=') ||
				cookie.startsWith('session=') ||
				cookie.startsWith('sessionid=') ||
				cookie.startsWith('session_id=')
		);

	console.log(
		`[${new Date().toISOString()}] auth.svelte.ts: Current session cookies visible to JS:`,
		sessionCookies
	);
	console.log(
		`[${new Date().toISOString()}] auth.svelte.ts: All cookies visible to JS:`,
		allCookies
	);
	console.log(
		`[${new Date().toISOString()}] auth.svelte.ts: NOTE: HttpOnly cookies (like 'id') are NOT visible to JavaScript and cannot be deleted client-side!`
	);
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
import { goto } from '$app/navigation';

let initializePromise: Promise<void> | null = null;
let lastSessionCheck = 0;
const SESSION_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes

export async function initializeAuth(forceRecheck = false): Promise<void> {
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

	const now = Date.now();

	// Allow forced recheck (e.g., after connection restored) or if enough time has passed
	if (forceRecheck || now - lastSessionCheck > SESSION_CHECK_INTERVAL) {
		console.log(
			`[${new Date().toISOString()}] auth.svelte.ts: ${forceRecheck ? 'Forced' : 'Periodic'} session revalidation triggered`
		);
		initializePromise = null; // Clear cached promise
		lastSessionCheck = now;
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
				} else if (
					result.error.name === 'ApiResponseError' &&
					'statusCode' in result.error &&
					result.error.statusCode === 401
				) {
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
