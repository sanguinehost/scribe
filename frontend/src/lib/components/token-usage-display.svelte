<script lang="ts">
	import { Badge as BadgeComponent } from '$lib/components/ui/badge';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import type { TokenCountResponse as _TokenCountResponse } from '$lib/types';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';

	let {
		promptTokens = 0,
		completionTokens = 0,
		modelName = 'gemini-2.5-pro', // Default model for cost calculation
		loading = false,
		isEstimate = false,
		showCost = true,
		// Backend-provided cost values (preferred when available)
		actualCost = null,
		modifiedCost = null,
		creditCost: _creditCost = null
	} = $props<{
		promptTokens?: number | null;
		completionTokens?: number | null;
		modelName?: string | null;
		loading?: boolean;
		isEstimate?: boolean;
		showCost?: boolean;
		// Cost values from backend
		actualCost?: number | null;
		modifiedCost?: number | null;
		creditCost?: number | null;
	}>();

	// Gemini pricing (per 1M tokens)
	// When payments are enabled, uses customer pricing with 20% markup
	// Otherwise uses base Google API pricing
	const GEMINI_PRICING = ENABLE_PAYMENTS
		? {
				'gemini-2.5-flash': { input: 0.36, output: 3.0 }, // Customer: $0.30 + 20% = $0.36
				'gemini-2.5-flash-preview-09-2025': { input: 0.36, output: 3.0 }, // Same as flash
				'gemini-2.5-flash-image': { input: 0.36, output: 3.0 }, // Same as flash
				'gemini-2.5-pro': { input: 1.5, output: 12.0 }, // Customer: $1.25 + 20% = $1.50
				'gemini-2.5-flash-lite-preview-09-2025': { input: 0.12, output: 0.48 } // Customer: $0.10 + 20% = $0.12
			}
		: {
				'gemini-2.5-flash': { input: 0.3, output: 2.5 }, // Google API: $0.30/1M, $2.50/1M
				'gemini-2.5-flash-preview-09-2025': { input: 0.3, output: 2.5 }, // Same as flash
				'gemini-2.5-flash-image': { input: 0.3, output: 2.5 }, // Same as flash
				'gemini-2.5-pro': { input: 1.25, output: 10.0 }, // Google API: $1.25/1M, $10.00/1M
				'gemini-2.5-flash-lite-preview-09-2025': { input: 0.1, output: 0.4 } // Google API: $0.10/1M, $0.40/1M
			};

	const totalTokens = $derived((promptTokens || 0) + (completionTokens || 0));

	function normalizeModelName(model: string | null | undefined): string {
		if (!model) return 'gemini-2.5-pro';
		const normalized = model.toLowerCase().trim();
		// Handle common aliases and variations
		const aliases: Record<string, string> = {
			'gemini-2.5-flash-lite': 'gemini-2.5-flash-lite-preview-09-2025',
			'flash-lite': 'gemini-2.5-flash-lite-preview-09-2025',
			flash: 'gemini-2.5-flash',
			pro: 'gemini-2.5-pro'
		};
		return aliases[normalized] || normalized;
	}

	function calculateCost(tokens: number, rate: number): number {
		if (!tokens || tokens === 0) return 0;
		if (typeof rate !== 'number' || isNaN(rate)) return 0;
		return (tokens / 1_000_000) * rate;
	}

	const totalCost = $derived(() => {
		// PREFER backend-provided cost values when available
		// This ensures accuracy and consistency with billing
		if (ENABLE_PAYMENTS && modifiedCost != null && modifiedCost > 0) {
			// Payment feature enabled: use modified cost (with markup)
			return modifiedCost;
		} else if (actualCost != null && actualCost > 0) {
			// Fall back to actual API cost (always calculated by backend)
			return actualCost;
		}

		// FALLBACK: Calculate locally if backend values not available
		// (backwards compatibility for old messages or during streaming)
		const model = normalizeModelName(modelName);
		const pricing = GEMINI_PRICING[model as keyof typeof GEMINI_PRICING];
		if (!pricing) return 0;

		const inputCost = calculateCost(promptTokens || 0, pricing.input);
		const outputCost = calculateCost(completionTokens || 0, pricing.output);
		return inputCost + outputCost;
	});

	function formatCost(cost: number): string {
		if (typeof cost !== 'number' || isNaN(cost)) return '$0.00';
		if (cost === 0) return '$0.00';
		if (cost < 0.0001) {
			return '<$0.0001';
		}
		return `$${cost.toFixed(4)}`;
	}

	function formatTokens(tokens: number | undefined | null): string {
		if (!tokens || tokens === 0) {
			return '0';
		}
		if (tokens >= 1000) {
			return `${(tokens / 1000).toFixed(1)}k`;
		}
		return tokens.toString();
	}
</script>

{#if loading}
	<div class="flex items-center gap-2 text-xs text-muted-foreground">
		<Skeleton class="h-4 w-16" />
	</div>
{:else if totalTokens > 0}
	<div class="flex items-center gap-2 text-xs text-muted-foreground">
		{#if promptTokens && promptTokens > 0}
			<span class="text-blue-600 dark:text-blue-400">
				↑{formatTokens(promptTokens)} input
			</span>
		{/if}
		{#if completionTokens && completionTokens > 0}
			<span class="text-green-600 dark:text-green-400">
				↓{formatTokens(completionTokens)} output
			</span>
		{/if}
		<span class="font-medium">{formatTokens(totalTokens)} total</span>

		{#if showCost && totalCost() > 0}
			<BadgeComponent variant="outline" class="font-mono text-xs">
				{formatCost(totalCost())}
			</BadgeComponent>
		{/if}
		{#if isEstimate}
			<BadgeComponent variant="secondary" class="text-xs">Est.</BadgeComponent>
		{/if}
	</div>
{/if}
