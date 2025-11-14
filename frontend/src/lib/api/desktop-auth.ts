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
import { isDesktopMode } from '$lib/utils/features';

// Extend Window interface to include Tauri
declare global {
	interface Window {
		__TAURI__?: unknown;
	}
}

// Token storage interface matching Tauri backend StoredTokens
// CRITICAL: Now includes expires_in and matches Rust type exactly
// JavaScript uses camelCase, Rust uses snake_case with #[serde(rename_all = "camelCase")]
interface StoredTokens {
	accessToken: string; // Rust: access_token (serde camelCase)
	refreshToken: string; // Rust: refresh_token (serde camelCase)
	expiresIn: number; // Rust: expires_in (serde camelCase)
}

// Token refresh response from backend
interface TokenRefreshResponse {
	access_token: string;
	expires_in: number;
}

// Token login response from backend
export interface TokenLoginResponse {
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
	/**
	 * Base64-encoded Data Encryption Key (DEK) for Quick Start mode
	 * Only present for Quick Start mode, absent for password-based login
	 */
	dek?: string;
}

class DesktopAuthService {
	private accessToken: string | null = null;
	private refreshToken: string | null = null;
	private tokenExpiresAt: number | null = null;
	private refreshPromise: Promise<Result<void, ApiError>> | null = null;
	private dek: string | null = null; // Base64-encoded Data Encryption Key for Quick Start mode

	/**
	 * Initialize the service by loading stored tokens
	 */
	async initialize(): Promise<Result<boolean, ApiError>> {
		console.log('[DesktopAuth.initialize] START - checking environment');
		console.log('[DesktopAuth.initialize] browser:', browser, 'isDesktopMode():', isDesktopMode());
		if (!browser || !isDesktopMode()) {
			console.log('[DesktopAuth.initialize] Not in desktop environment, returning false');
			return ok(false); // Not in desktop environment
		}

		console.log('[DesktopAuth.initialize] Desktop environment detected, loading tokens...');
		try {
			const tokens = await invoke<StoredTokens | null>('load_tokens');
			console.log(
				'[DesktopAuth.initialize] load_tokens invoke completed:',
				tokens ? 'TOKENS FOUND' : 'NO TOKENS'
			);

			if (tokens) {
				this.accessToken = tokens.accessToken;
				this.refreshToken = tokens.refreshToken;
				// Use stored expires_in value (now available from unified type)
				this.tokenExpiresAt = Date.now() + tokens.expiresIn * 1000;
				console.log(
					'[DesktopAuth.initialize] Tokens set in memory, expiry:',
					new Date(this.tokenExpiresAt).toISOString()
				);

				// Load DEK if available (Quick Start mode)
				console.log('[DesktopAuth.initialize] Attempting to load DEK...');
				try {
					const dek = await invoke<string | null>('get_local_dek');
					if (dek) {
						this.dek = dek;
						console.log('[DesktopAuth.initialize] ✓ DEK loaded from secure storage');
					} else {
						console.warn(
							'[DesktopAuth.initialize] ⚠ No DEK found in storage (Quick Start not used)'
						);
					}
				} catch (error) {
					console.error(
						'[DesktopAuth.initialize] ✗ Failed to load DEK - API calls may fail:',
						error
					);
					// Continue initialization - DEK is only required for Quick Start mode
				}

				console.log('[DesktopAuth.initialize] ✓ SUCCESS - Tokens loaded from secure storage');
				return ok(true);
			}
			console.log('[DesktopAuth.initialize] No tokens found in storage');
			return ok(false);
		} catch (error) {
			console.error('[DesktopAuth.initialize] ✗ FAILED - Error loading tokens:', error);
			return err(new ApiNetworkError('Failed to load authentication tokens', error as Error));
		}
	}

	/**
	 * Login with credentials and store tokens
	 */
	async login(
		identifier: string,
		password: string
	): Promise<Result<TokenLoginResponse['user'], ApiError>> {
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
				return err(new ApiAuthError(errorData.message || 'Invalid credentials', response.status));
			}

			const data: TokenLoginResponse = await response.json();

			// Store tokens in memory
			this.accessToken = data.access_token;
			this.refreshToken = data.refresh_token;
			this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

			// Store DEK if present (Quick Start mode)
			// NOTE: DEK is already saved by backend during Quick Start registration
			// We just need to store it in memory for the X-Scribe-Dek header
			if (data.dek) {
				this.dek = data.dek;
				console.log('[DesktopAuth] DEK received from login response and stored in memory');
			}

			// Persist tokens to secure storage
			await invoke('save_tokens', {
				tokens: {
					accessToken: data.access_token,
					refreshToken: data.refresh_token,
					expiresIn: data.expires_in
				}
			});

			console.log('[DesktopAuth] Login successful, tokens saved');
			return ok(data.user);
		} catch (error) {
			console.error('[DesktopAuth] Login failed:', error);
			return err(new ApiNetworkError('Login request failed', error as Error));
		}
	}

	/**
	 * Auto-login for Quick Start mode (generates JWT tokens + DEK)
	 */
	async autoLogin(): Promise<Result<TokenLoginResponse['user'], ApiError>> {
		try {
			console.log('[DesktopAuth] Starting Quick Start auto-login...');
			// Call the auto-login endpoint
			const response = await fetch('/api/auth/desktop/auto-login', {
				method: 'GET'
			});

			if (!response.ok) {
				const errorData = await response.json().catch(() => ({ message: 'Auto-login failed' }));
				return err(new ApiAuthError(errorData.message || 'Auto-login failed', response.status));
			}

			const data: TokenLoginResponse = await response.json();
			console.log('[DesktopAuth] Auto-login response received:', {
				hasAccessToken: !!data.access_token,
				hasRefreshToken: !!data.refresh_token,
				hasDek: !!data.dek,
				expiresIn: data.expires_in
			});

			// Store tokens in memory
			this.accessToken = data.access_token;
			this.refreshToken = data.refresh_token;
			this.tokenExpiresAt = Date.now() + data.expires_in * 1000;

			// Store DEK if present (Quick Start mode - should always be present for auto-login)
			if (data.dek) {
				this.dek = data.dek;
				console.log('[DesktopAuth] DEK received from auto-login and stored in memory');

				// Persist DEK to secure storage
				await invoke('save_local_dek', { dek: data.dek });
				console.log('[DesktopAuth] DEK persisted to secure storage');
			} else {
				console.warn('[DesktopAuth] No DEK in auto-login response - this is unexpected!');
			}

			// Persist tokens to secure storage
			await invoke('save_tokens', {
				tokens: {
					accessToken: data.access_token,
					refreshToken: data.refresh_token,
					expiresIn: data.expires_in
				}
			});

			console.log('[DesktopAuth] Auto-login successful, tokens and DEK saved');
			return ok(data.user);
		} catch (error) {
			console.error('[DesktopAuth] Auto-login failed:', error);
			return err(new ApiNetworkError('Auto-login request failed', error as Error));
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

			// Clear tokens and DEK from memory
			this.accessToken = null;
			this.refreshToken = null;
			this.tokenExpiresAt = null;
			this.dek = null;

			// Clear tokens and DEK from secure storage
			await invoke('clear_tokens'); // This already clears DEK as well

			console.log('[DesktopAuth] Logout successful, tokens and DEK cleared');
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
		console.log(
			'[DesktopAuth.getAuthHeaders] Called - accessToken:',
			this.accessToken ? 'PRESENT' : 'MISSING',
			'dek:',
			this.dek ? 'PRESENT' : 'MISSING'
		);

		if (!this.accessToken) {
			console.warn(
				'[DesktopAuth.getAuthHeaders] ⚠ No access token available - returning empty headers'
			);
			return {};
		}

		const headers: Record<string, string> = {
			Authorization: `Bearer ${this.accessToken}`
		};

		// Include DEK header if available (Quick Start mode)
		if (this.dek) {
			headers['X-Scribe-Dek'] = this.dek;
			console.log(
				'[DesktopAuth.getAuthHeaders] ✓ Returning headers with Authorization + X-Scribe-Dek'
			);
		} else {
			console.log(
				'[DesktopAuth.getAuthHeaders] ✓ Returning headers with Authorization only (no DEK)'
			);
		}

		return headers;
	}

	/**
	 * Check if token needs refresh and refresh if necessary
	 */
	async ensureValidToken(): Promise<Result<void, ApiError>> {
		console.log('[DesktopAuth.ensureValidToken] Checking token validity...');

		// If no token in memory, try to reload from secure storage
		if (!this.accessToken || !this.refreshToken) {
			console.warn(
				'[DesktopAuth.ensureValidToken] ⚠ No tokens in memory - attempting to reload from secure storage'
			);

			try {
				const tokens = await invoke<StoredTokens | null>('load_tokens');
				if (tokens) {
					console.log('[DesktopAuth.ensureValidToken] ✓ Reloaded tokens from secure storage');
					this.accessToken = tokens.accessToken;
					this.refreshToken = tokens.refreshToken;
					this.tokenExpiresAt = Date.now() + tokens.expiresIn * 1000;

					// Try to reload DEK as well
					try {
						const dek = await invoke<string | null>('get_local_dek');
						if (dek) {
							this.dek = dek;
							console.log('[DesktopAuth.ensureValidToken] ✓ DEK reloaded from secure storage');
						}
					} catch (dekError) {
						console.warn('[DesktopAuth.ensureValidToken] DEK not available:', dekError);
					}

					// Continue with normal validation below
				} else {
					console.error(
						'[DesktopAuth.ensureValidToken] ✗ No tokens available - accessToken:',
						this.accessToken ? 'PRESENT' : 'MISSING',
						'refreshToken:',
						this.refreshToken ? 'PRESENT' : 'MISSING'
					);
					return err(new ApiAuthError('No authentication tokens available', 401));
				}
			} catch (error) {
				console.error('[DesktopAuth.ensureValidToken] Failed to load tokens from storage:', error);
				return err(new ApiAuthError('Failed to load authentication tokens', 401));
			}
		}

		// If token is still valid, no refresh needed
		const timeUntilExpiry = this.tokenExpiresAt ? this.tokenExpiresAt - Date.now() : 0;
		if (this.tokenExpiresAt && Date.now() < this.tokenExpiresAt - 60000) {
			// 1 minute buffer
			console.log(
				`[DesktopAuth.ensureValidToken] ✓ Token still valid (expires in ${Math.floor(timeUntilExpiry / 1000)}s)`
			);
			return ok(undefined);
		}

		console.log('[DesktopAuth.ensureValidToken] Token needs refresh or expired');

		// If already refreshing, wait for that to complete
		if (this.refreshPromise) {
			console.log('[DesktopAuth.ensureValidToken] Refresh already in progress, waiting...');
			return this.refreshPromise;
		}

		// Start refresh process
		console.log('[DesktopAuth.ensureValidToken] Starting token refresh...');
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
			return err(new ApiAuthError('No refresh token available', 401));
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
				this.dek = null;
				await invoke('clear_tokens').catch(() => {}); // Clears both tokens and DEK
				return err(new ApiAuthError('Token refresh failed, please login again', 401));
			}

			const data: TokenRefreshResponse = await response.json();

			// Update access token
			this.accessToken = data.access_token;
			this.tokenExpiresAt = Date.now() + data.expires_in * 1000;
			// Note: DEK is preserved in memory and storage during token refresh

			// Update stored tokens (DEK remains unchanged)
			await invoke('save_tokens', {
				tokens: {
					accessToken: data.access_token,
					refreshToken: this.refreshToken,
					expiresIn: data.expires_in
				}
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
