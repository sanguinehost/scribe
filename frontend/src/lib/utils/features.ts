/**
 * Feature flags for conditional compilation
 *
 * These flags control which features are compiled into the final bundle.
 * When a feature is disabled, the related code is completely eliminated
 * during the build process, reducing bundle size and attack surface.
 */

import { PUBLIC_ENABLE_LOCAL_LLM, PUBLIC_ENABLE_PAYMENTS } from '$env/static/public';

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
 * Type-safe feature flags object
 */
export const FEATURES = {
	localLlm: ENABLE_LOCAL_LLM,
	payments: ENABLE_PAYMENTS
} as const;

/**
 * Check if a specific feature is enabled at build time
 */
export function isFeatureEnabled(feature: keyof typeof FEATURES): boolean {
	return FEATURES[feature];
}
