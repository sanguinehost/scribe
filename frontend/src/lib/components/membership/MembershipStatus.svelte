<script lang="ts">
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import PlanBadge from './PlanBadge.svelte';
	import UsageIndicator from './UsageIndicator.svelte';
	import { CheckoutButton } from '$lib/components/payment';
	import { Button as ButtonComponent } from '$lib/components/ui/button';

	let {
		compact = false,
		showUpgradeButton = true,
		showUsage = true
	}: {
		compact?: boolean;
		showUpgradeButton?: boolean;
		showUsage?: boolean;
	} = $props();

	// Reactive subscription data
	const subscription = $derived(subscriptionStore.subscription);
	const _planFeatures = $derived(subscriptionStore.planFeatures);
	const usageLimits = $derived(subscriptionStore.usageLimits);
	const loading = $derived(subscriptionStore.loading);
	const error = $derived(subscriptionStore.error);
	const currentPlan = $derived(subscriptionStore.currentPlan);
	const _isSubscribed = $derived(subscriptionStore.isSubscribed);
	const isTrialing = $derived(subscriptionStore.isTrialing);
	const trialDaysRemaining = $derived(subscriptionStore.trialDaysRemaining);
	const daysUntilRenewal = $derived(subscriptionStore.daysUntilRenewal);
	const isAtLimit = $derived(subscriptionStore.isAtLimit);
	const isNearLimit = $derived(subscriptionStore.isNearLimit);

	function handleUpgrade() {
		window.location.href = '/pricing';
	}

	function handleManageSubscription() {
		// TODO: Navigate to subscription management page or modal
		console.log('Manage subscription clicked');
	}

	function getRenewalText(): string {
		if (!subscription) return '';

		if (subscription.cancel_at_period_end) {
			return `Cancels in ${daysUntilRenewal} days`;
		}

		if (isTrialing) {
			return `Trial ends in ${trialDaysRemaining} days`;
		}

		return `Renews in ${daysUntilRenewal} days`;
	}

	function getUpgradeRecommendation(): string | null {
		if (currentPlan === 'premium') return null;

		if (isAtLimit) {
			return 'Upgrade to continue chatting';
		}

		if (isNearLimit) {
			return 'Consider upgrading for more tokens';
		}

		if (currentPlan === 'free') {
			return 'Upgrade for more features';
		}

		return null;
	}
</script>

{#if ENABLE_PAYMENTS}
	<div class="membership-status {compact ? 'compact' : 'full'}">
		{#if loading}
			<div class="animate-pulse space-y-3">
				<div class="flex items-center gap-3">
					<div class="h-6 w-16 rounded-full bg-slate-200 dark:bg-slate-700"></div>
					<div class="h-4 w-20 rounded bg-slate-200 dark:bg-slate-700"></div>
				</div>
				{#if !compact && showUsage}
					<div class="h-20 rounded bg-slate-200 dark:bg-slate-700"></div>
				{/if}
			</div>
		{:else if error}
			<div class="text-sm text-red-600 dark:text-red-400">
				Error loading subscription: {error}
			</div>
		{:else}
			<!-- Plan info -->
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-3">
					<PlanBadge
						planType={currentPlan}
						status={subscription?.status}
						_size={compact ? 'sm' : 'md'}
						showStatus={true}
					/>

					{#if !compact}
						<div class="text-sm text-slate-600 dark:text-slate-300">
							{subscriptionStore.getPlanDisplayName()}
							{#if subscription && getRenewalText()}
								<div class="text-xs text-slate-500 dark:text-slate-400">
									{getRenewalText()}
								</div>
							{/if}
						</div>
					{/if}
				</div>

				{#if !compact && showUpgradeButton && currentPlan !== 'premium'}
					{#if currentPlan === 'free'}
						<ButtonComponent variant="default" size="sm" onclick={handleUpgrade}
							>Upgrade</ButtonComponent
						>
					{:else}
						<ButtonComponent variant="outline" size="sm" onclick={handleManageSubscription}
							>Manage</ButtonComponent
						>
					{/if}
				{/if}
			</div>

			<!-- Usage indicator -->
			{#if showUsage && !compact}
				<div class="mt-4">
					<UsageIndicator usage={usageLimits} showNumbers={true} showPercentage={false} />
				</div>
			{/if}

			<!-- Upgrade recommendations -->
			{#if !compact && getUpgradeRecommendation()}
				<div
					class="mt-3 rounded-lg border border-blue-200 bg-blue-50 p-3 dark:border-blue-800 dark:bg-blue-950/30"
				>
					<div class="flex items-center justify-between">
						<p class="text-sm text-blue-800 dark:text-blue-200">
							{getUpgradeRecommendation()}
						</p>
						{#if currentPlan === 'free'}
							<CheckoutButton
								planType="premium"
								buttonText="Upgrade Now"
								buttonClass="bg-blue-600 hover:bg-blue-700 text-white text-xs px-3 py-1 rounded"
							/>
						{:else}
							<ButtonComponent variant="default" size="sm" onclick={handleUpgrade}
								>View Plans</ButtonComponent
							>
						{/if}
					</div>
				</div>
			{/if}

			<!-- Trial notification -->
			{#if isTrialing && !compact}
				<div
					class="mt-3 rounded-lg border border-yellow-200 bg-yellow-50 p-3 dark:border-yellow-800 dark:bg-yellow-950/30"
				>
					<div class="flex items-center justify-between">
						<p class="text-sm text-yellow-800 dark:text-yellow-200">
							<strong>Trial Active:</strong>
							{trialDaysRemaining} days remaining
						</p>
						<ButtonComponent variant="default" size="sm" onclick={handleUpgrade}
							>Subscribe Now</ButtonComponent
						>
					</div>
				</div>
			{/if}
		{/if}
	</div>
{:else}
	<!-- Fallback when payments are disabled -->
	<div class="membership-status">
		<div class="flex items-center gap-3">
			<PlanBadge planType="free" _size={compact ? 'sm' : 'md'} />
			{#if !compact}
				<span class="text-sm text-slate-600 dark:text-slate-300"> Payments not available </span>
			{/if}
		</div>
	</div>
{/if}

<style>
	.membership-status.compact {
		padding: 0.5rem;
	}

	.membership-status.full {
		padding: 1rem;
	}
</style>
