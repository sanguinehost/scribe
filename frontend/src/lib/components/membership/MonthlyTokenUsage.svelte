<script lang="ts">
	import { Zap, Calendar, TrendingUp } from 'lucide-svelte';
	import type { UsageLimitsResponse } from '$lib/types';

	// Props
	export let usageLimits: UsageLimitsResponse | null = null;
	export let size: 'sm' | 'md' | 'lg' = 'md';
	export let showNumbers: boolean = true;
	export let showPeriod: boolean = true;

	// Computed properties
	$: tokensUsed = usageLimits ? usageLimits.tokens_used_total : 0;
	$: containerClass = getContainerClass();

	function getContainerClass(): string {
		const heights = {
			sm: 'h-1.5',
			md: 'h-2',
			lg: 'h-3'
		};
		return `w-full ${heights[size]}`;
	}

	function formatTokens(count: number): string {
		if (count >= 1000000) {
			return `${(count / 1000000).toFixed(1)}M`;
		}
		if (count >= 1000) {
			return `${(count / 1000).toFixed(1)}K`;
		}
		return count.toLocaleString();
	}

	function formatDate(dateString: string): string {
		const date = new Date(dateString);
		return date.toLocaleDateString('en-US', {
			month: 'short',
			day: 'numeric'
		});
	}

	function getRemainingTime(): string {
		if (!usageLimits) return '';

		const now = new Date();
		const periodEnd = new Date(usageLimits.period_end);
		const diffTime = periodEnd.getTime() - now.getTime();
		const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

		if (diffDays <= 0) return 'Resets soon';
		if (diffDays === 1) return 'Resets tomorrow';
		if (diffDays <= 7) return `Resets in ${diffDays} days`;
		if (diffDays <= 30) return `Resets in ${Math.ceil(diffDays / 7)} weeks`;
		return `Resets ${formatDate(usageLimits.period_end)}`;
	}

	function getUsageLabel(): string {
		if (!usageLimits) return 'Loading...';

		return formatTokens(tokensUsed);
	}
</script>

<div class="monthly-token-usage">
	{#if usageLimits}
		<div class="space-y-3">
			<!-- Header -->
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<svelte:component this={Zap} size={16} class="text-blue-500" />
					<span class="text-sm font-medium text-slate-900 dark:text-slate-100">
						Monthly Token Usage
					</span>
				</div>
				{#if showPeriod}
					<div class="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
						<Calendar size={12} />
						<span>{getRemainingTime()}</span>
					</div>
				{/if}
			</div>

			<!-- Usage numbers -->
			{#if showNumbers}
				<div class="flex items-center justify-between text-sm">
					<span class="font-medium text-slate-900 dark:text-slate-100">
						{getUsageLabel()} tokens used
					</span>
					<span class="text-slate-500 dark:text-slate-400"> This period </span>
				</div>
			{/if}

			<!-- Information display (no progress bar) -->
			<div
				class="rounded-lg border border-blue-200 bg-blue-50 p-3 dark:border-blue-800 dark:bg-blue-950/30"
			>
				<div class="flex items-start gap-2">
					<TrendingUp size={14} class="mt-0.5 text-blue-600 dark:text-blue-400" />
					<div class="text-xs text-blue-800 dark:text-blue-200">
						<p class="font-medium">Usage tracking for administrative purposes</p>
						<p class="mt-1 text-blue-700 dark:text-blue-300">
							This data helps us understand platform usage patterns and ensure fair resource
							allocation.
						</p>
					</div>
				</div>
			</div>

			<!-- Billing period info -->
			{#if showPeriod}
				<div class="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
					<span>
						{formatDate(usageLimits.period_start)} - {formatDate(usageLimits.period_end)}
					</span>
				</div>
			{/if}
		</div>
	{:else}
		<!-- Loading state -->
		<div class="animate-pulse space-y-3">
			<div class="flex justify-between">
				<div class="h-4 w-24 rounded bg-slate-200 dark:bg-slate-700"></div>
				<div class="h-4 w-16 rounded bg-slate-200 dark:bg-slate-700"></div>
			</div>
			<div class="flex justify-between">
				<div class="h-4 w-20 rounded bg-slate-200 dark:bg-slate-700"></div>
				<div class="h-4 w-12 rounded bg-slate-200 dark:bg-slate-700"></div>
			</div>
			<div class={`rounded-full bg-slate-200 dark:bg-slate-700 ${containerClass}`}></div>
			<div class="h-3 w-32 rounded bg-slate-200 dark:bg-slate-700"></div>
		</div>
	{/if}
</div>

<style>
	.monthly-token-usage {
		min-width: 0; /* Prevent flex overflow */
	}

	.progress-container {
		position: relative;
		box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
	}

	.normal-glow {
		box-shadow: 0 0 4px rgba(59, 130, 246, 0.3);
	}

	.warning-glow {
		box-shadow: 0 0 6px rgba(245, 158, 11, 0.4);
		animation: warningPulse 2s ease-in-out infinite;
	}

	.critical-glow {
		box-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
		animation: criticalPulse 1s ease-in-out infinite;
	}

	@keyframes warningPulse {
		0%,
		100% {
			box-shadow: 0 0 6px rgba(245, 158, 11, 0.4);
		}
		50% {
			box-shadow: 0 0 12px rgba(245, 158, 11, 0.6);
		}
	}

	@keyframes criticalPulse {
		0%,
		100% {
			box-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
		}
		50% {
			box-shadow: 0 0 16px rgba(239, 68, 68, 0.8);
		}
	}
</style>
