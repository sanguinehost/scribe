/**
 * Desktop-specific authentication using JWT tokens
 * Integrates with Tauri for secure token storage
 */

import { invoke } from '@tauri-apps/api/core';
import { browser } from '$app/environment';
import type { Result } from 'neverthrow';
import { ok, err } from 'neverthrow';
import type { ApiError } from '$lib/errors/api';
import { ApiAuthError, ApiNetworkError } from '$lib/errors/api';

// Token storage interface matching Tauri backend
interface TokenPair {
	access_token: string;
	refresh_token: string;
}

// Token refresh response from backend
interface TokenRefreshResponse {
	access_token: string;
	expires_in: number;
}

// Token login response from backend
interface TokenLoginResponse {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	user: {
		user_id: string;
		username: string;
		email: string;
		role: string;
		recovery_key: string | null;
		default_persona_id: string | null;
	};
}

class DesktopAuthService {
	private accessToken: string | null = null;
	private refreshToken: string | null = null;
	private tokenExpiresAt: number | null = null;
	private refreshPromise: Promise<Result<void, ApiError>> | null = null;

	/**
	 * Initialize the service by loading stored tokens
	 */
	async initialize(): Promise<Result<boolean, ApiError>> {
		if (!browser || !window.__TAURI__) {
			return ok(false); // Not in desktop environment
		}

		try {
			const tokens = await invoke<TokenPair | null>('load_tokens');
			if (tokens) {
				this.accessToken = tokens.access_token;
				this.refreshToken = tokens.refresh_token;
				// Set expiry to 15 minutes from now (we don't know actual expiry on load)
				this.tokenExpiresAt = Date.now() + 15 * 60 * 1000;
				console.log('[DesktopAuth] Tokens loaded from secure storage');
				return ok(true);
			}
			console.log('[DesktopAuth] No tokens found in storage');
			return ok(false);
		} catch (error) {
			console.error('[DesktopAuth] Failed to load tokens:', error);
			return err(new ApiNetworkError('Failed to load authentication tokens', error as Error));
		}
	}

	/**
	 * Login with credentials and store tokens
	 */
	async login(identifier: string, password: string): Promise<Result<TokenLoginResponse['user'], ApiError>> {
		try {
			// Call the token login endpoint
			const response = await fetch('/api/auth/token/login', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ identifier, password })
			});

			if (!response.ok) {
				const errorData = await response.json().catch(() => ({ message: 'Login failed' }));
				return err(new ApiAuthError(errorData.message || 'Invalid credentials'));
			}

			const data: TokenLoginResponse = await response.json();

			// Store tokens in memory
			this.accessToken = data.access_token;
			this.refreshToken = data.refresh_token;
			this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

			// Persist tokens to secure storage
			await invoke('save_tokens', {
				accessToken: data.access_token,
				refreshToken: data.refresh_token
			});

			console.log('[DesktopAuth] Login successful, tokens saved');
			return ok(data.user);
		} catch (error) {
			console.error('[DesktopAuth] Login failed:', error);
			return err(new ApiNetworkError('Login request failed', error as Error));
		}
	}

	/**
	 * Logout and clear stored tokens
	 */
	async logout(): Promise<Result<void, ApiError>> {
		try {
			// Call logout endpoint (informational)
			await fetch('/api/auth/token/logout', {
				method: 'POST',
				headers: this.getAuthHeaders()
			}).catch(() => {}); // Ignore errors on logout

			// Clear tokens from memory
			this.accessToken = null;
			this.refreshToken = null;
			this.tokenExpiresAt = null;

			// Clear tokens from secure storage
			await invoke('clear_tokens');

			console.log('[DesktopAuth] Logout successful, tokens cleared');
			return ok(undefined);
		} catch (error) {
			console.error('[DesktopAuth] Logout failed:', error);
			return err(new ApiNetworkError('Logout failed', error as Error));
		}
	}

	/**
	 * Get authorization headers for API requests
	 */
	getAuthHeaders(): Record<string, string> {
		if (!this.accessToken) {
			return {};
		}
		return {
			'Authorization': `Bearer ${this.accessToken}`
		};
	}

	/**
	 * Check if token needs refresh and refresh if necessary
	 */
	async ensureValidToken(): Promise<Result<void, ApiError>> {
		// If no token, user needs to login
		if (!this.accessToken || !this.refreshToken) {
			return err(new ApiAuthError('No authentication tokens available'));
		}

		// If token is still valid, no refresh needed
		if (this.tokenExpiresAt && Date.now() < this.tokenExpiresAt - 60000) { // 1 minute buffer
			return ok(undefined);
		}

		// If already refreshing, wait for that to complete
		if (this.refreshPromise) {
			return this.refreshPromise;
		}

		// Start refresh process
		this.refreshPromise = this.refreshAccessToken();
		const result = await this.refreshPromise;
		this.refreshPromise = null;
		return result;
	}

	/**
	 * Refresh the access token using the refresh token
	 */
	private async refreshAccessToken(): Promise<Result<void, ApiError>> {
		if (!this.refreshToken) {
			return err(new ApiAuthError('No refresh token available'));
		}

		try {
			console.log('[DesktopAuth] Refreshing access token...');
			const response = await fetch('/api/auth/token/refresh', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ refresh_token: this.refreshToken })
			});

			if (!response.ok) {
				// Refresh failed, user needs to login again
				this.accessToken = null;
				this.refreshToken = null;
				this.tokenExpiresAt = null;
				await invoke('clear_tokens').catch(() => {});
				return err(new ApiAuthError('Token refresh failed, please login again'));
			}

			const data: TokenRefreshResponse = await response.json();

			// Update access token
			this.accessToken = data.access_token;
			this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

			// Update stored tokens
			await invoke('save_tokens', {
				accessToken: data.access_token,
				refreshToken: this.refreshToken
			});

			console.log('[DesktopAuth] Access token refreshed successfully');
			return ok(undefined);
		} catch (error) {
			console.error('[DesktopAuth] Token refresh failed:', error);
			return err(new ApiNetworkError('Token refresh failed', error as Error));
		}
	}

	/**
	 * Check if user is authenticated
	 */
	isAuthenticated(): boolean {
		return !!this.accessToken;
	}
}

// Export singleton instance
export const desktopAuth = new DesktopAuthService();

// Helper to check if running in Tauri desktop environment
export function isDesktopApp(): boolean {
	return browser && typeof window !== 'undefined' && '__TAURI__' in window;
}