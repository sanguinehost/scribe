<script lang="ts">
	import { Zap, Calendar, TrendingUp } from 'lucide-svelte';
	import type { UsageLimitsResponse } from '$lib/types';

	// Props
	export let usageLimits: UsageLimitsResponse | null = null;
	export let size: 'sm' | 'md' | 'lg' = 'md';
	export let showNumbers: boolean = true;
	export let showPeriod: boolean = true;

	// Computed properties
	$: tokensUsed = usageLimits ? usageLimits.tokens_limit - usageLimits.tokens_remaining : 0;
	$: usagePercentage = calculateUsagePercentage();
	$: isNearLimit = usagePercentage >= 80;
	$: isAtLimit = usagePercentage >= 100;
	$: statusColor = getStatusColor();
	$: containerClass = getContainerClass();

	function calculateUsagePercentage(): number {
		if (!usageLimits || usageLimits.is_unlimited) {
			return 0;
		}

		const used = usageLimits.tokens_limit - usageLimits.tokens_remaining;
		return Math.min(100, (used / usageLimits.tokens_limit) * 100);
	}

	function getStatusColor(): string {
		if (isAtLimit) return 'bg-red-500';
		if (isNearLimit) return 'bg-yellow-500';
		return 'bg-blue-500';
	}

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

		if (usageLimits.is_unlimited) {
			return 'Unlimited';
		}

		return `${formatTokens(tokensUsed)} / ${formatTokens(usageLimits.tokens_limit)}`;
	}
</script>

<div class="monthly-token-usage">
	{#if usageLimits}
		{#if usageLimits.is_unlimited}
			<div class="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
				<div class="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
				<Zap size={16} class="text-blue-500" />
				<span class="font-medium">Unlimited tokens</span>
			</div>
		{:else}
			<div class="space-y-3">
				<!-- Header -->
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<Zap size={16} class="text-blue-500" />
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
							{getUsageLabel()} tokens
						</span>
						<span class="text-slate-500 dark:text-slate-400">
							{Math.round(usagePercentage)}% used
						</span>
					</div>
				{/if}

				<!-- Progress bar -->
				<div class={`bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden ${containerClass} progress-container`}>
					<div
						class={`${statusColor} transition-all duration-300 ease-out h-full ${
							isAtLimit ? 'animate-pulse critical-glow' : isNearLimit ? 'warning-glow' : 'normal-glow'
						}`}
						style="width: {usagePercentage}%"
						role="progressbar"
						aria-valuenow={usagePercentage}
						aria-valuemin={0}
						aria-valuemax={100}
						aria-label={`Monthly token usage: ${Math.round(usagePercentage)}% used`}
					></div>
				</div>

				<!-- Billing period info -->
				{#if showPeriod}
					<div class="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
						<span>
							{formatDate(usageLimits.period_start)} - {formatDate(usageLimits.period_end)}
						</span>
						{#if isAtLimit}
							<span class="text-red-600 dark:text-red-400 font-medium flex items-center gap-1">
								<TrendingUp size={12} />
								Limit reached
							</span>
						{:else if isNearLimit}
							<span class="text-yellow-600 dark:text-yellow-400 font-medium flex items-center gap-1">
								<TrendingUp size={12} />
								Near limit
							</span>
						{/if}
					</div>
				{/if}
			</div>
		{/if}
	{:else}
		<!-- Loading state -->
		<div class="space-y-3 animate-pulse">
			<div class="flex justify-between">
				<div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-24"></div>
				<div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-16"></div>
			</div>
			<div class="flex justify-between">
				<div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-20"></div>
				<div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-12"></div>
			</div>
			<div class={`bg-slate-200 dark:bg-slate-700 rounded-full ${containerClass}`}></div>
			<div class="h-3 bg-slate-200 dark:bg-slate-700 rounded w-32"></div>
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
		0%, 100% {
			box-shadow: 0 0 6px rgba(245, 158, 11, 0.4);
		}
		50% {
			box-shadow: 0 0 12px rgba(245, 158, 11, 0.6);
		}
	}

	@keyframes criticalPulse {
		0%, 100% {
			box-shadow: 0 0 8px rgba(239, 68, 68, 0.5);
		}
		50% {
			box-shadow: 0 0 16px rgba(239, 68, 68, 0.8);
		}
	}
</style>