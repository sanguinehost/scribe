import { writable, derived, get } from 'svelte/store';

// Credit balance and usage information
export interface CreditBalance {
	balance: number;
	lifetime_earned: number;
	lifetime_spent: number;
	last_monthly_grant?: string;
	updated_at?: string;
}

// Credit transaction
export interface CreditTransaction {
	id: string;
	amount: number;
	balance_after: number;
	transaction_type: string;
	description: string;
	metadata?: any;
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
		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const response = await fetch('/api/payment/credits/balance', {
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json'
				}
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.message || 'Failed to fetch credit balance');
			}

			const data = await response.json();

			update((state) => ({
				...state,
				balance: data,
				isLoading: false,
				lastFetch: new Date()
			}));

			return data;
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Failed to fetch credit balance';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw error;
		}
	}

	// Fetch transaction history
	async function fetchTransactions(limit: number = 50, offset: number = 0) {
		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const response = await fetch(`/api/payment/credits/transactions?limit=${limit}&offset=${offset}`, {
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json'
				}
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.message || 'Failed to fetch transactions');
			}

			const data = await response.json();

			update((state) => ({
				...state,
				transactions: data.transactions || [],
				isLoading: false
			}));

			return data.transactions;
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Failed to fetch transactions';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw error;
		}
	}

	// Fetch available credit packages
	async function fetchPackages() {
		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const response = await fetch('/api/payment/credits/packages', {
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json'
				}
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.message || 'Failed to fetch credit packages');
			}

			const data = await response.json();

			update((state) => ({
				...state,
				packages: data.packages || [],
				isLoading: false
			}));

			return data.packages;
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Failed to fetch credit packages';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw error;
		}
	}

	// Purchase credits
	async function purchaseCredits(packageId: string) {
		update((state) => ({ ...state, isLoading: true, error: null }));

		try {
			const response = await fetch('/api/payment/credits/purchase', {
				method: 'POST',
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ package_id: packageId })
			});

			if (!response.ok) {
				const error = await response.json();
				throw new Error(error.message || 'Failed to purchase credits');
			}

			const data = await response.json();

			// Refresh balance after purchase
			await fetchBalance();

			update((state) => ({
				...state,
				isLoading: false
			}));

			return data;
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Failed to purchase credits';
			update((state) => ({
				...state,
				isLoading: false,
				error: errorMessage
			}));
			throw error;
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
		const state = get({ subscribe });
		return state.balance ? state.balance.balance >= requiredCredits : false;
	}

	// Get credit cost for a specific model
	function getModelCreditCost(modelName: string): number {
		// These should match the backend configuration
		const modelCosts: { [key: string]: number } = {
			'gemini-2.5-pro': 50,
			'gemini-2.5-flash': 10,
			'gemini-2.5-flash-8b': 5,
			'gemini-2.5-flash-lite': 0,
			'o1-preview': 100,
			'o1-mini': 75,
			'gpt-4o': 40,
			'gpt-4o-mini': 15,
			'claude-3-5-sonnet-20241022': 60,
			'claude-3-5-haiku-20241022': 20,
		};

		return modelCosts[modelName] || 10; // Default to 10 credits
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
			lastFetch: null
		});
	}

	return {
		subscribe,
		fetchBalance,
		fetchTransactions,
		fetchPackages,
		purchaseCredits,
		updateDailyUsage,
		hasSufficientCredits,
		getModelCreditCost,
		reset
	};
}

// Export the store instance
export const creditStore = createCreditStore();

// Derived store for formatted balance display
export const formattedBalance = derived(
	creditStore,
	($creditStore) => {
		if (!$creditStore.balance) return '---';
		return $creditStore.balance.balance.toLocaleString();
	}
);

// Derived store for usage percentage
export const usagePercentage = derived(
	creditStore,
	($creditStore) => {
		if (!$creditStore.dailyUsage) return 0;
		return Math.min(100, $creditStore.dailyUsage.usage_percentage);
	}
);

// Derived store for whether user is near or over limit
export const isNearLimit = derived(
	creditStore,
	($creditStore) => {
		if (!$creditStore.dailyUsage) return false;
		return $creditStore.dailyUsage.usage_percentage >= 80;
	}
);

export const isOverLimit = derived(
	creditStore,
	($creditStore) => {
		if (!$creditStore.dailyUsage) return false;
		return $creditStore.dailyUsage.usage_percentage >= 100;
	}
);