<script lang="ts">
	import { Badge } from '$lib/components/ui/badge';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import type { TokenCountResponse } from '$lib/types';

	let {
		promptTokens = 0,
		completionTokens = 0,
		modelName = 'gemini-2.5-pro', // Default model for cost calculation
		loading = false,
		isEstimate = false,
		showCost = true
	} = $props<{
		promptTokens?: number | null;
		completionTokens?: number | null;
		modelName?: string | null;
		loading?: boolean;
		isEstimate?: boolean;
		showCost?: boolean;
	}>();

	// Gemini pricing (per 1M tokens) - Updated with correct official pricing
	const GEMINI_PRICING = {
		'gemini-2.5-flash': { input: 0.3, output: 2.5 },
		'gemini-2.5-pro': { input: 1.25, output: 10.0 }, // For prompts <= 200k tokens
		'gemini-2.5-flash-lite-preview': { input: 0.1, output: 0.4 }
	};

	const totalTokens = $derived((promptTokens || 0) + (completionTokens || 0));

	function calculateCost(tokens: number, rate: number): number {
		if (!tokens || tokens === 0) return 0;
		return (tokens / 1_000_000) * rate;
	}

	const totalCost = $derived(() => {
		const model = modelName || 'gemini-2.5-pro';
		const pricing = GEMINI_PRICING[model as keyof typeof GEMINI_PRICING];
		if (!pricing) return 0;

		const inputCost = calculateCost(promptTokens || 0, pricing.input);
		const outputCost = calculateCost(completionTokens || 0, pricing.output);
		return inputCost + outputCost;
	});

	function formatCost(cost: number): string {
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
			<Badge variant="outline" class="font-mono text-xs">
				{formatCost(totalCost())}
			</Badge>
		{/if}
		{#if isEstimate}
			<Badge variant="secondary" class="text-xs">Est.</Badge>
		{/if}
	</div>
{/if}
