<script lang="ts">
	import type { PlanType, SubscriptionStatus } from '$lib/types';
	import { Gift, Star, Crown } from 'lucide-svelte';

	// Props
	export let planType: PlanType = 'free';
	export let status: SubscriptionStatus | null = null;
	export let size: 'sm' | 'md' | 'lg' = 'md';
	export let showStatus: boolean = false;

	// Computed properties
	$: badgeClass = getBadgeClass(planType, size);
	$: displayText = getDisplayText(planType, status, showStatus);
	$: iconSize = getIconSize(size);

	function getBadgeClass(plan: PlanType, size: 'sm' | 'md' | 'lg'): string {
		const baseClass = 'inline-flex items-center font-medium rounded-full';

		// Size classes
		const sizeClasses = {
			sm: 'px-2 py-1 text-xs',
			md: 'px-2.5 py-1.5 text-sm',
			lg: 'px-3 py-2 text-base'
		};

		// Plan-specific colors
		const planClasses = {
			free: 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200',
			basic: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 ring-1 ring-blue-600/20',
			premium: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200 ring-1 ring-purple-600/20'
		};

		return `${baseClass} ${sizeClasses[size]} ${planClasses[plan]}`;
	}

	function getDisplayText(plan: PlanType, status: SubscriptionStatus | null, showStatus: boolean): string {
		const planNames = {
			free: 'Free',
			basic: 'Basic',
			premium: 'Premium'
		};

		// Handle undefined or invalid plan types
		const safePlan = plan || 'free';
		const planName = planNames[safePlan] || 'Free';

		if (!showStatus || !status) {
			return planName;
		}

		// Add status context for non-free plans
		if (safePlan !== 'free') {
			switch (status) {
				case 'trialing':
					return `${planName} Trial`;
				case 'canceled':
					return `${planName} (Canceled)`;
				case 'past_due':
					return `${planName} (Past Due)`;
				case 'unpaid':
					return `${planName} (Unpaid)`;
				case 'incomplete':
					return `${planName} (Incomplete)`;
				case 'active':
				default:
					return planName;
			}
		}

		return planName;
	}

	function getIconSize(size: 'sm' | 'md' | 'lg'): number {
		switch (size) {
			case 'sm':
				return 12;
			case 'md':
				return 14;
			case 'lg':
				return 16;
			default:
				return 14;
		}
	}
</script>

<span class={badgeClass} title="Current subscription plan">
	<span class="mr-1 inline-flex" aria-hidden="true">
		{#if planType === 'free'}
			<Gift size={iconSize} />
		{:else if planType === 'basic'}
			<Star size={iconSize} />
		{:else if planType === 'premium'}
			<Crown size={iconSize} />
		{/if}
	</span>
	{displayText}
</span>

<style>
	/* Additional styles for visual polish */
	span {
		transition: all 0.2s ease;
	}
</style>