/**
 * Centralized Authentication State Management
 *
 * This module provides global authentication state to prevent multiple re-authentication
 * cycles when DEK (Data Encryption Key) is missing after server restarts.
 *
 * Problem: Without centralized state, multiple concurrent API requests each independently
 * detect DEK missing and trigger separate re-authentication flows, requiring users
 * to log in 3-4 times after every server restart.
 *
 * Solution: Single source of truth for DEK missing state with request queuing
 * and automatic retry after successful re-authentication.
 */

interface FailedRequest {
	promise: () => Promise<unknown>;
	resolve: (value: unknown) => void;
	reject: (reason?: unknown) => void;
}

interface AuthState {
	isDekMissing: boolean;
	isReAuthInProgress: boolean;
	failedRequests: Map<string, FailedRequest>;
}

class AuthStateManager {
	private state: AuthState = {
		isDekMissing: false,
		isReAuthInProgress: false,
		failedRequests: new Map<string, FailedRequest>()
	};

	/**
	 * Ensure valid authentication before making API requests
	 */
	async ensureValidAuthentication(): Promise<void> {
		console.log('[authState] ensureValidAuthentication called', {
			isDekMissing: this.state.isDekMissing,
			isReAuthInProgress: this.state.isReAuthInProgress
		});

		if (this.state.isDekMissing && !this.state.isReAuthInProgress) {
			console.log('[authState] DEK missing detected, starting re-authentication flow');
			this.state.isReAuthInProgress = true;

			// Dispatch event to trigger modal display
			// The layout component listens for this and shows the ReAuthModal
			console.log('[authState] Dispatching auth:dek-missing event');
			window.dispatchEvent(
				new CustomEvent('auth:dek-missing', { detail: { reason: 'dek_missing' } })
			);

			// Wait for re-authentication to complete
			// The ReAuthModal will dispatch auth:reauth-complete event
			await this.waitForReAuthSuccess();

			console.log('[authState] Re-authentication successful, clearing DEK missing state');
			this.state.isReAuthInProgress = false;
			this.state.isDekMissing = false;

			// Retry all failed requests
			console.log(`[authState] Retrying ${this.state.failedRequests.size} failed requests`);
			this.state.failedRequests.forEach((request) => {
				request.resolve(undefined);
			});
			this.state.failedRequests.clear();
		} else {
			console.log('[authState] Skipping re-authentication trigger', {
				isDekMissing: this.state.isDekMissing,
				isReAuthInProgress: this.state.isReAuthInProgress
			});
		}
	}

	/**
	 * Wait for re-authentication to complete
	 */
	private waitForReAuthSuccess(): Promise<void> {
		return new Promise((resolve) => {
			const handler = (event: Event) => {
				const customEvent = event as CustomEvent;
				if (customEvent.detail?.success === true) {
					window.removeEventListener('auth:reauth-complete', handler);
					resolve();
				}
			};

			window.addEventListener('auth:reauth-complete', handler);

			// Timeout after 30 seconds to prevent hanging
			setTimeout(() => {
				window.removeEventListener('auth:reauth-complete', handler);
				console.warn('[authState] Re-authentication timeout');
				resolve();
			}, 30000);
		});
	}

	/**
	 * Mark DEK as missing
	 */
	setDekMissing(): void {
		console.log('[authState] DEK missing flag set');
		this.state.isDekMissing = true;
	}

	/**
	 * Mark DEK as valid
	 */
	clearDekMissing(): void {
		console.log('[authState] DEK missing flag cleared');
		this.state.isDekMissing = false;
	}

	/**
	 * Check if DEK is currently missing
	 */
	isDekMissing(): boolean {
		return this.state.isDekMissing;
	}

	/**
	 * Check if re-authentication is currently in progress
	 */
	isReAuthInProgress(): boolean {
		return this.state.isReAuthInProgress;
	}

	/**
	 * Get the reactive state for component access
	 */
	getState() {
		return this.state;
	}
}

// Global singleton instance
const authStateManager = new AuthStateManager();

// Export convenience functions
export async function ensureValidAuthentication(): Promise<void> {
	return authStateManager.ensureValidAuthentication();
}

export function setDekMissing(): void {
	authStateManager.setDekMissing();
}

export function clearDekMissing(): void {
	authStateManager.clearDekMissing();
}

export function isDekMissing(): boolean {
	return authStateManager.isDekMissing();
}

export function isReAuthInProgress(): boolean {
	return authStateManager.isReAuthInProgress();
}

export const authState = authStateManager.getState();
