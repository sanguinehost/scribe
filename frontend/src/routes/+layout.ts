import { isDesktopMode } from '$lib/utils/features';
import { apiClient } from '$lib/api';
import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';

// Disable SSR for Tauri desktop app
// This is REQUIRED per Tauri + SvelteKit documentation:
// https://v2.tauri.app/develop/sveltekit/#disable-ssr
//
// Tauri apps run entirely in the browser context with no Node.js server,
// so server-side rendering cannot work. All data loading must happen
// client-side via API calls to the Rust backend.
export const ssr = false;

// Disable prerendering to run in SPA mode
// Prerendering would fail for dynamic routes (e.g., /chat/[chatId])
// SPA mode works better for Tauri as everything loads client-side
export const prerender = false;

// Track if we've attempted auto-login to avoid repeated calls on every navigation
let autoLoginAttempted = false;

/**
 * Root layout loader
 * Handles desktop-specific initialization:
 * - Checks if desktop setup is complete, redirects to welcome wizard if not
 * - Attempts auto-login for Quick Start mode on first app load
 */
export const load: LayoutLoad = async ({ url, fetch }) => {
	console.log('[+layout.ts] Root layout load function called');
	console.log('[+layout.ts] Current URL:', url.pathname);
	console.log('[+layout.ts] window object exists:', typeof window !== 'undefined');

	// Desktop-specific initialization
	const isDesktop = isDesktopMode();
	console.log('[+layout.ts] isDesktopMode() returned:', isDesktop);

	if (isDesktop) {
		console.log('[+layout.ts] Desktop mode detected, calling getDesktopConfig...');
		const configResult = await apiClient.getDesktopConfig(fetch);
		console.log('[+layout.ts] getDesktopConfig result:', configResult.isOk() ? 'OK' : 'ERROR');

		if (configResult.isOk()) {
			const config = configResult.value;
			console.log('[+layout.ts] Desktop config:', config);

			// Always redirect to welcome wizard if setup not complete
			// (unless we're already on the welcome page)
			if (!config.setup_complete && url.pathname !== '/welcome') {
				console.log('[+layout.ts] Setup not complete, redirecting to /welcome');
				throw redirect(302, '/welcome');
			}

			// For Quick Start mode, attempt auto-login once per app session
			// This restores the session on app restart without requiring credentials
			if (
				config.setup_complete &&
				config.auth_mode === 'quick_start' &&
				!autoLoginAttempted
			) {
				console.log('[+layout.ts] Quick Start mode detected, attempting auto-login...');
				autoLoginAttempted = true;
				// Auto-login sets session cookie - the auth store will pick it up
				// If it fails, user will see login page (graceful degradation)
				const autoLoginResult = await apiClient.desktopAutoLogin(fetch);
				console.log('[+layout.ts] Auto-login result:', autoLoginResult.isOk() ? 'OK' : 'ERROR');
			}

			// For Account mode, let normal auth flow handle login
			// User must provide credentials via the standard auth page
		} else {
			console.error('[+layout.ts] getDesktopConfig failed:', configResult.error);
		}
		// If config check fails, continue anyway - might be first run or API issue
	}

	console.log('[+layout.ts] Returning from load function');
	return {};
};
