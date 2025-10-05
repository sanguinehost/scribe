import { writable, derived, get } from 'svelte/store';
import { PAYMENT_FEATURES } from '$lib/utils/features';
import { apiClient as _apiClient } from '$lib/api';
import type { CreditBalanceResponse } from '$lib/types/payment';

// Credit balance and usage information - use the response type for compatibility
export type CreditBalance = CreditBalanceResponse;

// Credit transaction
export interface CreditTransaction {
	id: string;
	amount: number;
	balance_after: number;
	transaction_type: string;
	description: string;
	metadata?: unknown;
	reference_id?: string;
	created_at: string;
}

// Credit package for purchasing
export interface CreditPackage {
	package_id: string;
	name: string;
	credits: number;
	bonus_percentage?: number;
	price_cents: number;
	currency: string;
	active: boolean;
	display_order: number;
}

// Daily usage info
export interface DailyUsage {
	message_count: number;
	daily_limit: number;
	tier: string;
	usage_percentage: number;
	reset_time?: string;
}

// Credit store state
interface CreditState {
	balance: CreditBalance | null;
	transactions: CreditTransaction[];
	packages: CreditPackage[];
	dailyUsage: DailyUsage | null;
	isLoading: boolean;
	error: string | null;
	lastFetch: Date | null;
	modelCosts?: { [key: string]: number };
	tokenPricing?: { [key: string]: unknown };
	contextMultipliers?: { [key: string]: number };
}

// Create the main credit store
function createCreditStore() {
	const { subscribe, set, update } = writable<CreditState>({
		balance: null,
		transactions: [],
		packages: [],
		dailyUsage: null,
		isLoading: false,
		error: null,
		lastFetch: null
	});

	// Fetch credit balance
	async function fetchBalance() {
		if (!PAYMENT_FEATURES.credits) {
			update((state) => ({ ...state, error: 'Credits feature not enabled' }));
			throw new Error('Credits feature not enabled');
		}

		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const result = await _apiClient.getCreditBalance();

			if (result.isErr()) {
				throw new Error(result.error.message || 'Failed to fetch credit balance');
			}

			const data = result.value;

			update((state) => ({
				...state,
				balance: data,
				isLoading: false,
				lastFetch: new Date()
			}));

			return data;
		} catch (_error) {
			const errorMessage =
				_error instanceof Error ? _error.message : 'Failed to fetch credit balance';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw _error;
		}
	}

	// Fetch transaction history
	async function fetchTransactions(limit: number = 50, offset: number = 0) {
		if (!PAYMENT_FEATURES.credits) {
			update((state) => ({ ...state, error: 'Credits feature not enabled' }));
			throw new Error('Credits feature not enabled');
		}

		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const result = await _apiClient.getCreditTransactions(limit, offset);

			if (result.isErr()) {
				throw new Error(result.error.message || 'Failed to fetch transactions');
			}

			const data = result.value;

			update((state) => ({
				...state,
				transactions: data.transactions || [],
				isLoading: false
			}));

			return data.transactions;
		} catch (_error) {
			const errorMessage =
				_error instanceof Error ? _error.message : 'Failed to fetch transactions';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw _error;
		}
	}

	// Fetch available credit packages
	async function fetchPackages() {
		if (!PAYMENT_FEATURES.credits) {
			update((state) => ({ ...state, error: 'Credits feature not enabled' }));
			throw new Error('Credits feature not enabled');
		}

		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const result = await _apiClient.getCreditPackages();

			if (result.isErr()) {
				throw new Error(result.error.message || 'Failed to fetch credit packages');
			}

			const data = result.value;

			update((state) => ({
				...state,
				packages: data.packages || [],
				isLoading: false
			}));

			return data.packages;
		} catch (_error) {
			const errorMessage =
				_error instanceof Error ? _error.message : 'Failed to fetch credit packages';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw _error;
		}
	}

	// Purchase credits
	async function purchaseCredits(packageId: string) {
		if (!PAYMENT_FEATURES.credits) {
			update((state) => ({ ...state, error: 'Credits feature not enabled' }));
			throw new Error('Credits feature not enabled');
		}

		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const result = await _apiClient.purchaseCredits(packageId);

			if (result.isErr()) {
				throw new Error(result.error.message || 'Failed to purchase credits');
			}

			const data = result.value;

			// Refresh balance after purchase
			await fetchBalance();

			update((state) => ({
				...state,
				isLoading: false
			}));

			return data;
		} catch (_error) {
			const errorMessage = _error instanceof Error ? _error.message : 'Failed to purchase credits';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw _error;
		}
	}

	// Update daily usage from response headers
	function updateDailyUsage(headers: Headers) {
		const dailyLimit = headers.get('X-Daily-Limit');
		const dailyUsage = headers.get('X-Daily-Usage');
		const tier = headers.get('X-Subscription-Tier');

		if (dailyLimit && dailyUsage) {
			const limit = parseInt(dailyLimit, 10);
			const usage = parseInt(dailyUsage, 10);
			const percentage = Math.round((usage / limit) * 100);

			update((state) => ({
				...state,
				dailyUsage: {
					message_count: usage,
					daily_limit: limit,
					tier: tier || 'free',
					usage_percentage: percentage,
					reset_time: '00:00 UTC'
				}
			}));
		}
	}

	// Calculate if user has sufficient credits for a model
	function hasSufficientCredits(requiredCredits: number): boolean {
		if (!PAYMENT_FEATURES.credits) {
			return true; // If credits are disabled, assume unlimited access
		}
		const state = get({ subscribe });
		return state.balance ? state.balance.balance >= requiredCredits : false;
	}

	// Fetch model costs from backend
	async function fetchModelCosts() {
		if (!PAYMENT_FEATURES.credits) {
			return null;
		}

		try {
			const result = await _apiClient.getModelCosts();

			if (result.isErr()) {
				throw new Error(result.error.message || 'Failed to fetch model costs');
			}

			const data = result.value;

			update((state) => ({
				...state,
				modelCosts: data.model_costs || {},
				tokenPricing: data.token_pricing || {},
				contextMultipliers: data.context_multipliers || {}
			}));

			return data;
		} catch (_error) {
			const errorMessage = _error instanceof Error ? _error.message : 'Failed to fetch model costs';
			console.error('Failed to fetch model costs:', errorMessage);
			// Don't update error state as this is non-critical
			return null;
		}
	}

	// Get credit cost for a specific model
	function getModelCreditCost(modelName: string): number {
		if (!PAYMENT_FEATURES.credits) {
			return 0; // If credits are disabled, all models are free
		}

		const state = get({ subscribe });

		// Use dynamic costs if available
		if (state.modelCosts && state.modelCosts[modelName] !== undefined) {
			return state.modelCosts[modelName];
		}

		// Fallback to hardcoded defaults for resilience
		const defaultCosts: { [key: string]: number } = {
			'gemini-2.5-pro': 50,
			'gemini-2.5-flash': 10,
			'gemini-2.5-flash-8b': 5,
			'gemini-2.5-flash-lite': 0,
			'o1-preview': 100,
			'o1-mini': 75,
			'gpt-4o': 40,
			'gpt-4o-mini': 15,
			'claude-3-5-sonnet-20241022': 60,
			'claude-3-5-haiku-20241022': 20
		};

		return defaultCosts[modelName] || 10; // Default to 10 credits
	}

	// Reset store
	function reset() {
		set({
			balance: null,
			transactions: [],
			packages: [],
			dailyUsage: null,
			isLoading: false,
			error: null,
			lastFetch: null,
			modelCosts: undefined,
			tokenPricing: undefined,
			contextMultipliers: undefined
		});
	}

	return {
		subscribe,
		fetchBalance,
		fetchTransactions,
		fetchPackages,
		purchaseCredits,
		fetchModelCosts,
		updateDailyUsage,
		hasSufficientCredits,
		getModelCreditCost,
		reset
	};
}

// Export the store instance
export const creditStore = createCreditStore();

// Derived store for formatted balance display
export const formattedBalance = derived(creditStore, ($creditStore) => {
	if (!$creditStore.balance) return '---';
	return $creditStore.balance.balance.toLocaleString();
});

// Derived store for usage percentage
export const usagePercentage = derived(creditStore, ($creditStore) => {
	if (!$creditStore.dailyUsage) return 0;
	return Math.min(100, $creditStore.dailyUsage.usage_percentage);
});

// Derived store for whether user is near or over limit
export const isNearLimit = derived(creditStore, ($creditStore) => {
	if (!$creditStore.dailyUsage) return false;
	return $creditStore.dailyUsage.usage_percentage >= 80;
});

export const isOverLimit = derived(creditStore, ($creditStore) => {
	if (!$creditStore.dailyUsage) return false;
	return $creditStore.dailyUsage.usage_percentage >= 100;
});
