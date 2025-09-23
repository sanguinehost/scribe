<script lang="ts">
	import type { UsageLimitsResponse } from '$lib/types';

	// Props
	export let usage: UsageLimitsResponse | null = null;
	export let size: 'sm' | 'md' | 'lg' = 'md';
	export let showNumbers: boolean = true;
	export let showPercentage: boolean = false;
	export let orientation: 'horizontal' | 'vertical' = 'horizontal';

	// Computed properties
	$: usagePercentage = calculateUsagePercentage(usage);
	$: isNearLimit = usagePercentage >= 80;
	$: isAtLimit = usagePercentage >= 100;
	$: statusColor = getStatusColor(usagePercentage);
	$: containerClass = getContainerClass(size, orientation);
	$: progressBarClass = getProgressBarClass(size, orientation);

	function calculateUsagePercentage(usage: UsageLimitsResponse | null): number {
		if (!usage || usage.is_unlimited) {
			return 0;
		}
		
		const used = usage.tokens_limit - usage.tokens_remaining;
		return Math.min(100, (used / usage.tokens_limit) * 100);
	}

	function getStatusColor(percentage: number): string {
		if (percentage >= 95) return 'bg-red-500';
		if (percentage >= 80) return 'bg-yellow-500';
		return 'bg-green-500';
	}

	function getContainerClass(size: 'sm' | 'md' | 'lg', orientation: 'horizontal' | 'vertical'): string {
		if (orientation === 'vertical') {
			const widths = { sm: 'w-2', md: 'w-3', lg: 'w-4' };
			return `${widths[size]} h-full`;
		} else {
			const heights = { sm: 'h-1.5', md: 'h-2', lg: 'h-3' };
			return `w-full ${heights[size]}`;
		}
	}

	function getProgressBarClass(size: 'sm' | 'md' | 'lg', orientation: 'horizontal' | 'vertical'): string {
		let baseClass = `${statusColor} transition-all duration-300 ease-out rounded-full`;
		
		// Add pulsing animation when at critical levels
		if (isAtLimit) {
			baseClass += ' animate-pulse';
		} else if (isNearLimit && usagePercentage >= 90) {
			baseClass += ' animate-pulse';
		}
		
		return baseClass;
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

	function getRemainingTime(usage: UsageLimitsResponse | null): string {
		if (!usage) return '';
		
		const now = new Date();
		const periodEnd = new Date(usage.period_end);
		const diffTime = periodEnd.getTime() - now.getTime();
		const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
		
		if (diffDays <= 0) return 'Resets soon';
		if (diffDays === 1) return 'Resets tomorrow';
		return `Resets in ${diffDays} days`;
	}

	function getUsageLabel(): string {
		if (!usage) return 'Loading...';

		if (usage.is_unlimited) {
			return 'Unlimited';
		}

		const used = usage.tokens_limit - usage.tokens_remaining;
		return `${formatTokens(used)}`;
	}
</script>

<div class="usage-indicator">
	{#if usage}
		{#if usage.is_unlimited}
			<div class="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
				<div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
				<span class="font-medium">Unlimited tokens</span>
			</div>
		{:else}
			<div class="space-y-2">
				<!-- Usage text and percentage -->
				{#if showNumbers || showPercentage}
					<div class="flex items-center justify-between text-sm">
						{#if showNumbers}
							<span class="font-medium text-slate-900 dark:text-slate-100">
								{getUsageLabel()} tokens this month
							</span>
						{/if}
						{#if showPercentage}
							<span class="text-slate-500 dark:text-slate-400">
								{Math.round(usagePercentage)}% used
							</span>
						{/if}
					</div>
				{/if}

				<!-- Progress bar -->
				<div class={`bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden ${containerClass} progress-container`}>
					<div 
						class={`${progressBarClass} ${isAtLimit ? 'critical-glow' : isNearLimit ? 'warning-glow' : 'normal-glow'}`}
						style={orientation === 'horizontal' 
							? `width: ${usagePercentage}%` 
							: `height: ${usagePercentage}%`
						}
						role="progressbar"
						aria-valuenow={usagePercentage}
						aria-valuemin={0}
						aria-valuemax={100}
						aria-label={`Token usage: ${Math.round(usagePercentage)}% used`}
					></div>
				</div>

				<!-- Status text -->
				<div class="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
					<span>{getRemainingTime(usage)}</span>
					{#if isAtLimit}
						<span class="text-red-600 dark:text-red-400 font-medium">Limit reached</span>
					{:else if isNearLimit}
						<span class="text-yellow-600 dark:text-yellow-400 font-medium">Near limit</span>
					{/if}
				</div>
			</div>
		{/if}
	{:else}
		<!-- Loading state -->
		<div class="space-y-2 animate-pulse">
			<div class="flex justify-between">
				<div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-20"></div>
				<div class="h-4 bg-slate-200 dark:bg-slate-700 rounded w-12"></div>
			</div>
			<div class={`bg-slate-200 dark:bg-slate-700 rounded-full ${containerClass}`}></div>
			<div class="h-3 bg-slate-200 dark:bg-slate-700 rounded w-16"></div>
		</div>
	{/if}
</div>

<style>
	.usage-indicator {
		min-width: 0; /* Prevent flex overflow */
	}

	.progress-container {
		position: relative;
		box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
	}

	.normal-glow {
		box-shadow: 0 0 4px rgba(34, 197, 94, 0.3);
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