<script lang="ts">
	import { MessageCircle, AlertTriangle, CheckCircle } from 'lucide-svelte';
	import type { PlanType } from '$lib/types';

	// Props
	export let messageCount: number = 0;
	export let planType: PlanType = 'free';
	export let isThrottled: boolean = false;
	export let throttleDelay: number = 0;
	export let size: 'sm' | 'md' | 'lg' = 'md';

	// Daily limits based on plan
	const dailyLimits: Record<PlanType, { limit: number; type: 'hard' | 'soft' }> = {
		free: { limit: 20, type: 'hard' },
		basic: { limit: 100, type: 'soft' },
		premium: { limit: 200, type: 'soft' }
	};

	// Computed properties with safety checks
	$: currentLimit = dailyLimits[planType] || dailyLimits.free;
	$: usagePercentage = currentLimit ? Math.min(100, (messageCount / currentLimit.limit) * 100) : 0;
	$: isNearLimit = usagePercentage >= 80;
	$: isAtLimit = usagePercentage >= 100;
	$: isOverLimit = currentLimit ? messageCount > currentLimit.limit : false;
	$: statusColor = getStatusColor();
	$: containerClass = getContainerClass();
	$: statusText = getStatusText();
	$: statusIcon = getStatusIcon();

	function getStatusColor(): string {
		if (!currentLimit) return 'bg-gray-500';
		if (isOverLimit && currentLimit.type === 'hard') return 'bg-red-500';
		if (isOverLimit) return 'bg-orange-500';
		if (isAtLimit) return 'bg-yellow-500';
		if (isNearLimit) return 'bg-yellow-400';
		return 'bg-green-500';
	}

	function getContainerClass(): string {
		const heights = {
			sm: 'h-1.5',
			md: 'h-2',
			lg: 'h-3'
		};
		return `w-full ${heights[size]}`;
	}

	function getStatusText(): string {
		if (!currentLimit) {
			return 'Loading limits...';
		}
		if (currentLimit.type === 'hard' && isAtLimit) {
			return 'Daily limit reached';
		}
		if (isThrottled) {
			return `Throttled (${throttleDelay}ms delay)`;
		}
		if (isOverLimit) {
			return `${messageCount - currentLimit.limit} over soft limit`;
		}
		if (isNearLimit) {
			return `${currentLimit.limit - messageCount} messages remaining`;
		}
		return `${messageCount} / ${currentLimit.limit} messages today`;
	}

	function getStatusIcon(): 'check' | 'warning' | 'error' {
		if (!currentLimit) return 'check';
		if (currentLimit.type === 'hard' && isAtLimit) return 'error';
		if (isThrottled || isOverLimit) return 'warning';
		return 'check';
	}

	function formatTime(): string {
		const now = new Date();
		const midnight = new Date();
		midnight.setHours(24, 0, 0, 0);
		const msUntilMidnight = midnight.getTime() - now.getTime();
		const hoursUntilReset = Math.floor(msUntilMidnight / (1000 * 60 * 60));
		const minutesUntilReset = Math.floor((msUntilMidnight % (1000 * 60 * 60)) / (1000 * 60));

		if (hoursUntilReset > 0) {
			return `Resets in ${hoursUntilReset}h ${minutesUntilReset}m`;
		}
		return `Resets in ${minutesUntilReset} minutes`;
	}
</script>

<div class="daily-usage-container">
	<div class="mb-2 flex items-center justify-between">
		<div class="flex items-center gap-2">
			<MessageCircle size={16} class="text-slate-500 dark:text-slate-400" />
			<span class="text-sm font-medium text-slate-900 dark:text-slate-100"> Daily Messages </span>
			{#if currentLimit && currentLimit.type === 'soft'}
				<span class="text-xs italic text-slate-500 dark:text-slate-400"> (soft limit) </span>
			{/if}
		</div>
		<div class="flex items-center gap-1">
			{#if statusIcon === 'error'}
				<AlertTriangle size={14} class="text-red-500" />
			{:else if statusIcon === 'warning'}
				<AlertTriangle size={14} class="text-yellow-500" />
			{:else}
				<CheckCircle size={14} class="text-green-500" />
			{/if}
			<span class="text-sm text-slate-600 dark:text-slate-300">
				{statusText}
			</span>
		</div>
	</div>

	<!-- Progress bar -->
	<div class={`overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700 ${containerClass}`}>
		<div
			class={`${statusColor} h-full transition-all duration-300 ease-out ${
				isThrottled || (currentLimit && currentLimit.type === 'hard' && isAtLimit)
					? 'animate-pulse'
					: ''
			}`}
			style="width: {Math.min(100, usagePercentage)}%"
			role="progressbar"
			aria-valuenow={messageCount}
			aria-valuemin={0}
			aria-valuemax={currentLimit?.limit || 0}
			aria-label={`Daily message usage: ${messageCount} of ${currentLimit?.limit || 0}`}
		></div>
	</div>

	<!-- Additional info -->
	<div class="mt-1 flex items-center justify-between">
		<span class="text-xs text-slate-500 dark:text-slate-400">
			{formatTime()}
		</span>
		{#if isThrottled}
			<span class="text-xs font-medium text-orange-500 dark:text-orange-400">
				Response delay active
			</span>
		{:else if currentLimit && currentLimit.type === 'soft' && isOverLimit}
			<span class="text-xs text-yellow-500 dark:text-yellow-400"> Soft limit exceeded </span>
		{/if}
	</div>
</div>

<style>
	.daily-usage-container {
		min-width: 0;
	}
</style>
