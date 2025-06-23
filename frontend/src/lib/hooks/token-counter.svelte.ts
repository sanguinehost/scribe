import { apiClient } from '$lib/api';
import type { TokenCountRequest, TokenCountResponse } from '$lib/types';

interface TokenCountState {
	loading: boolean;
	data: TokenCountResponse | null;
	error: string | null;
}

/**
 * Hook for counting tokens using the backend hybrid token counter
 */
export function useTokenCounter() {
	let state = $state<TokenCountState>({
		loading: false,
		data: null,
		error: null
	});

	/**
	 * Count tokens for the given text
	 */
	async function countTokens(request: TokenCountRequest): Promise<TokenCountResponse | null> {
		state.loading = true;
		state.error = null;
		state.data = null;

		try {
			const result = await apiClient.countTokens(request);

			if (result.isOk()) {
				state.data = result.value;
				return result.value;
			} else {
				state.error = result.error.message;
				console.error('Token counting failed:', result.error);
				return null;
			}
		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
			state.error = errorMessage;
			console.error('Token counting error:', error);
			return null;
		} finally {
			state.loading = false;
		}
	}

	/**
	 * Count tokens for text with default options
	 */
	async function countTokensSimple(
		text: string,
		model?: string,
		useApiCounting = false
	): Promise<TokenCountResponse | null> {
		return countTokens({
			text,
			model,
			use_api_counting: useApiCounting
		});
	}

	/**
	 * Reset the state
	 */
	function reset() {
		state.loading = false;
		state.data = null;
		state.error = null;
	}

	return {
		get loading() {
			return state.loading;
		},
		get data() {
			return state.data;
		},
		get error() {
			return state.error;
		},
		countTokens,
		countTokensSimple,
		reset
	};
}

/**
 * Utility function to estimate cost from token count response
 */
export function estimateCost(
	tokenData: TokenCountResponse,
	isOutput = false
): { cost: number; formattedCost: string } {
	// Gemini pricing (per 1M tokens) - Updated with correct official pricing
	const GEMINI_PRICING = {
		'gemini-2.5-flash': { input: 0.30, output: 2.50 },
		'gemini-2.5-pro': { input: 1.25, output: 10.00 }, // For prompts <= 200k tokens
		'gemini-2.5-flash-lite-preview': { input: 0.10, output: 0.40 }
	};

	const pricing = GEMINI_PRICING[tokenData.model_used as keyof typeof GEMINI_PRICING];
	if (!pricing) {
		return { cost: 0, formattedCost: 'Unknown' };
	}

	const rate = isOutput ? pricing.output : pricing.input;
	const cost = (tokenData.total / 1_000_000) * rate;

	const formattedCost = cost < 0.001 ? '<$0.001' : `$${cost.toFixed(3)}`;

	return { cost, formattedCost };
}

/**
 * Format token count for display
 */
export function formatTokens(tokens: number): string {
	if (tokens >= 1_000_000) {
		return `${(tokens / 1_000_000).toFixed(1)}M`;
	} else if (tokens >= 1000) {
		return `${(tokens / 1000).toFixed(1)}k`;
	}
	return tokens.toString();
}