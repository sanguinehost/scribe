<script lang="ts">
	import type { PlanType, SubscriptionStatus } from '$lib/types';

	// Props
	export let planType: PlanType = 'free';
	export let status: SubscriptionStatus | null = null;
	export let size: 'sm' | 'md' | 'lg' = 'md';
	export let showStatus: boolean = false;

	// Computed properties
	$: badgeClass = getBadgeClass(planType, size);
	$: displayText = getDisplayText(planType, status, showStatus);

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
			pro: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 ring-1 ring-blue-600/20',
			enterprise: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200 ring-1 ring-purple-600/20'
		};

		return `${baseClass} ${sizeClasses[size]} ${planClasses[plan]}`;
	}

	function getDisplayText(plan: PlanType, status: SubscriptionStatus | null, showStatus: boolean): string {
		const planNames = {
			free: 'Free',
			pro: 'Pro',
			enterprise: 'Enterprise'
		};

		if (!showStatus || !status) {
			return planNames[plan];
		}

		// Add status context for non-free plans
		if (plan !== 'free') {
			switch (status) {
				case 'trialing':
					return `${planNames[plan]} Trial`;
				case 'canceled':
					return `${planNames[plan]} (Canceled)`;
				case 'past_due':
					return `${planNames[plan]} (Past Due)`;
				case 'unpaid':
					return `${planNames[plan]} (Unpaid)`;
				case 'incomplete':
					return `${planNames[plan]} (Incomplete)`;
				case 'active':
				default:
					return planNames[plan];
			}
		}

		return planNames[plan];
	}

	function getPlanIcon(plan: PlanType): string {
		switch (plan) {
			case 'free':
				return '🆓';
			case 'pro':
				return '⭐';
			case 'enterprise':
				return '👑';
			default:
				return '🆓';
		}
	}
</script>

<span class={badgeClass} title="Current subscription plan">
	<span class="mr-1" aria-hidden="true">{getPlanIcon(planType)}</span>
	{displayText}
</span>

<style>
	/* Additional styles for visual polish */
	span {
		transition: all 0.2s ease;
	}
</style>