import { writable, derived } from 'svelte/store';
import { PAYMENT_FEATURES } from '$lib/utils/features';
import { apiClient } from '$lib/api';
import type { UsageResponse, SoftLimitStatus, DailyUsage } from '$lib/types/payment';

// Usage store state
interface UsageState {
	daily?: DailyUsage;
	monthly?: {
		messages_sent: number;
		tokens_consumed: number;
		credits_spent: number;
		period_start: string;
		period_end: string;
	};
	softLimitStatus?: SoftLimitStatus | null;
	isLoading: boolean;
	error: string | null;
	lastFetch: Date | null;
}

// Create the main usage store
function createUsageStore() {
	const { subscribe, set, update } = writable<UsageState>({
		daily: undefined,
		monthly: undefined,
		softLimitStatus: null,
		isLoading: false,
		error: null,
		lastFetch: null
	});

	// Fetch current usage stats including soft limit status
	async function fetchUsageStats() {
		if (!PAYMENT_FEATURES.enabled) {
			update((state) => ({ ...state, error: 'Payment features not enabled' }));
			throw new Error('Payment features not enabled');
		}

		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const result = await apiClient.getUsageStats();

			if (result.isOk()) {
				const data = result.value;
				update((state) => ({
					...state,
					daily: data.daily,
					monthly: data.monthly,
					softLimitStatus: data.soft_limit_status || null,
					isLoading: false,
					lastFetch: new Date()
				}));
				return data;
			} else {
				const errorMessage = result.error.message || 'Failed to fetch usage stats';
				update((state) => ({
					...state,
					isLoading: false,
					error: errorMessage
				}));
				throw new Error(errorMessage);
			}
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Failed to fetch usage stats';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw error;
		}
	}

	// Update soft limit status from response headers (if available)
	function updateSoftLimitFromHeaders(headers: Headers) {
		const softLimitActive = headers.get('X-Soft-Limit-Active');
		const softLimitDelay = headers.get('X-Soft-Limit-Delay');

		if (softLimitActive !== null && softLimitDelay !== null) {
			const active = softLimitActive === 'true';
			const delayMs = parseInt(softLimitDelay, 10) || 0;

			update((state) => ({
				...state,
				softLimitStatus: active ? {
					active,
					current_delay_ms: delayMs,
					next_threshold: undefined, // We'd need more headers for this
					warning_message: active ? `Rate limiting active with ${delayMs}ms delay` : undefined
				} : null
			}));
		}
	}

	// Reset store
	function reset() {
		set({
			daily: undefined,
			monthly: undefined,
			softLimitStatus: null,
			isLoading: false,
			error: null,
			lastFetch: null
		});
	}

	// Auto-refresh usage stats (useful for monitoring soft limits)
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	function startAutoRefresh(intervalMs: number = 30000) { // 30 seconds default
		if (refreshInterval) {
			clearInterval(refreshInterval);
		}

		refreshInterval = setInterval(() => {
			if (PAYMENT_FEATURES.enabled) {
				fetchUsageStats().catch(console.error);
			}
		}, intervalMs);
	}

	function stopAutoRefresh() {
		if (refreshInterval) {
			clearInterval(refreshInterval);
			refreshInterval = null;
		}
	}

	return {
		subscribe,
		fetchUsageStats,
		updateSoftLimitFromHeaders,
		startAutoRefresh,
		stopAutoRefresh,
		reset
	};
}

// Export the store instance
export const usageStore = createUsageStore();

// Derived store for soft limit status
export const softLimitStatus = derived(
	usageStore,
	($usageStore) => {
		if (!PAYMENT_FEATURES.softLimits) return null;
		return $usageStore.softLimitStatus || null;
	}
);

// Derived store for whether soft limits are active
export const isSoftLimitActive = derived(
	softLimitStatus,
	($softLimitStatus) => {
		return $softLimitStatus?.active || false;
	}
);

// Derived store for current soft limit delay
export const currentSoftLimitDelay = derived(
	softLimitStatus,
	($softLimitStatus) => {
		return $softLimitStatus?.current_delay_ms || 0;
	}
);

// Derived store for whether user should be warned about upcoming limits
export const shouldShowSoftLimitWarning = derived(
	softLimitStatus,
	($softLimitStatus) => {
		if (!PAYMENT_FEATURES.softLimits || !$softLimitStatus) return false;

		// Show warning if active OR if there's a next threshold coming up
		return $softLimitStatus.active || !!$softLimitStatus.next_threshold;
	}
);