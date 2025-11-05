/**
 * Feature flags for conditional compilation
 *
 * These flags control which features are compiled into the final bundle.
 * When a feature is disabled, the related code is completely eliminated
 * during the build process, reducing bundle size and attack surface.
 */

import {
	PUBLIC_ENABLE_LOCAL_LLM,
	PUBLIC_ENABLE_PAYMENTS,
	PUBLIC_ENABLE_CREDITS,
	PUBLIC_ENABLE_SOFT_LIMITS,
	PUBLIC_API_URL
} from '$env/static/public';

/**
 * Whether local LLM features should be included in the build
 * This includes the LlmStore, model management UI, and local model API calls
 */
export const ENABLE_LOCAL_LLM = PUBLIC_ENABLE_LOCAL_LLM === 'true';

/**
 * Whether payment and billing features should be included in the build
 * This includes subscription management, usage tracking, and billing UI
 */
export const ENABLE_PAYMENTS = PUBLIC_ENABLE_PAYMENTS === 'true';

/**
 * Whether credit system features should be included in the build
 * This includes credit balance, credit purchases, and credit usage for premium models
 */
export const ENABLE_CREDITS = PUBLIC_ENABLE_CREDITS === 'true';

/**
 * Whether soft limit features should be included in the build
 * This includes daily usage limits, throttling warnings, and usage tracking UI
 */
export const ENABLE_SOFT_LIMITS = PUBLIC_ENABLE_SOFT_LIMITS === 'true';

/**
 * Type-safe feature flags object
 */
export const FEATURES = {
	localLlm: ENABLE_LOCAL_LLM,
	payments: ENABLE_PAYMENTS,
	credits: ENABLE_CREDITS,
	softLimits: ENABLE_SOFT_LIMITS
} as const;

/**
 * Payment-specific feature flags (static constants for optimal dead code elimination)
 */
export const ENABLE_PAYMENT_CREDITS = ENABLE_PAYMENTS && ENABLE_CREDITS;
export const ENABLE_PAYMENT_SOFT_LIMITS = ENABLE_PAYMENTS && ENABLE_SOFT_LIMITS;
export const ENABLE_PAYMENT_SUBSCRIPTIONS = ENABLE_PAYMENTS;

/**
 * Legacy PAYMENT_FEATURES object for backward compatibility
 * TODO: Migrate all usage to direct constants above for better dead code elimination
 */
export const PAYMENT_FEATURES = {
	enabled: ENABLE_PAYMENTS,
	credits: ENABLE_PAYMENT_CREDITS,
	softLimits: ENABLE_PAYMENT_SOFT_LIMITS,
	subscriptions: ENABLE_PAYMENT_SUBSCRIPTIONS
} as const;

/**
 * Check if a specific feature is enabled at build time
 */
export function isFeatureEnabled(feature: keyof typeof FEATURES): boolean {
	return FEATURES[feature];
}

/**
 * Runtime check for desktop mode (Tauri)
 *
 * Desktop mode is detected by checking if the API URL uses the custom scribe:// protocol
 * which is only configured for desktop builds (see .env.production.desktop)
 *
 * @returns true if running in Tauri desktop app, false if running in browser
 */
export function isDesktopMode(): boolean {
	// Check if we're in a browser environment first
	if (typeof window === 'undefined') {
		console.log('[isDesktopMode] window is undefined, returning false');
		return false;
	}

	// Primary check: Desktop builds use scribe://localhost as API URL
	// Cloud builds use https://... or relative URLs
	const usesCustomProtocol = PUBLIC_API_URL?.startsWith('scribe://');
	console.log('[isDesktopMode] PUBLIC_API_URL:', PUBLIC_API_URL);
	console.log('[isDesktopMode] usesCustomProtocol check:', usesCustomProtocol);

	// Fallback checks for additional validation
	const hasTauriApi = typeof window.__TAURI__ !== 'undefined';
	console.log('[isDesktopMode] window.__TAURI__ check:', hasTauriApi);

	// Check for scribe:// custom protocol in window location
	const hasCustomProtocolInLocation =
		typeof window.location !== 'undefined' && window.location.protocol === 'scribe:';
	console.log('[isDesktopMode] window.location.protocol:', window.location?.protocol);
	console.log('[isDesktopMode] hasCustomProtocolInLocation check:', hasCustomProtocolInLocation);

	// Desktop mode is true if any desktop indicator is present
	const result = usesCustomProtocol || hasTauriApi || hasCustomProtocolInLocation;
	console.log('[isDesktopMode] Final result:', result);
	return result;
}
