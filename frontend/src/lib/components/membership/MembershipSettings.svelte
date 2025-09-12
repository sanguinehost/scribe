<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Separator } from '$lib/components/ui/separator';
	import PlanBadge from './PlanBadge.svelte';
	import UsageIndicator from './UsageIndicator.svelte';
	import { CheckoutButton } from '$lib/components/payment';

	// Reactive subscription data
	$: subscription = subscriptionStore.subscription;
	$: planFeatures = subscriptionStore.planFeatures;
	$: usageLimits = subscriptionStore.usageLimits;
	$: loading = subscriptionStore.loading;
	$: error = subscriptionStore.error;
	$: currentPlan = subscriptionStore.currentPlan;
	$: isSubscribed = subscriptionStore.isSubscribed;
	$: isTrialing = subscriptionStore.isTrialing;
	$: trialDaysRemaining = subscriptionStore.trialDaysRemaining;
	$: daysUntilRenewal = subscriptionStore.daysUntilRenewal;

	function handleViewPricing() {
		// Instead of navigating to pricing page, we'll show upgrade options directly
		// This function is kept for backward compatibility but could be removed
		console.log('View pricing clicked - showing upgrade options directly');
	}

	function handleManageSubscription() {
		// TODO: Implement proper subscription management
		// For now, show available options based on current subscription status
		if (!subscription) {
			toast.error('No active subscription found.');
			return;
		}

		// This could be enhanced to:
		// 1. Show a modal with management options (cancel, reactivate, change plan)
		// 2. Use Paddle's customer portal if available
		// 3. Redirect to a dedicated subscription management page
		
		toast.info('Subscription management coming soon. Contact support for assistance.');
		console.log('Manage subscription clicked for:', subscription);
	}

	function getRenewalText(): string {
		if (!subscription) return '';
		
		if (subscription.cancel_at_period_end) {
			return `Subscription cancels in ${daysUntilRenewal} days`;
		}
		
		if (isTrialing) {
			return `Trial ends in ${trialDaysRemaining} days`;
		}
		
		return `Subscription renews in ${daysUntilRenewal} days`;
	}

	function formatDate(dateString: string): string {
		const date = new Date(dateString);
		return date.toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'long',
			day: 'numeric'
		});
	}
</script>

{#if ENABLE_PAYMENTS}
	<Card class="w-full">
		<CardHeader>
			<CardTitle class="flex items-center gap-2">
				<svg
					xmlns="http://www.w3.org/2000/svg"
					width="20"
					height="20"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					class="lucide lucide-credit-card"
				>
					<rect width="20" height="14" x="2" y="5" rx="2"/>
					<line x1="2" x2="22" y1="10" y2="10"/>
				</svg>
				Membership & Billing
			</CardTitle>
		</CardHeader>
		<CardContent class="space-y-6">
			{#if loading}
				<div class="space-y-4 animate-pulse">
					<div class="h-8 bg-slate-200 dark:bg-slate-700 rounded"></div>
					<div class="h-20 bg-slate-200 dark:bg-slate-700 rounded"></div>
					<div class="h-16 bg-slate-200 dark:bg-slate-700 rounded"></div>
				</div>
			{:else if error}
				<div class="p-4 border border-red-200 dark:border-red-800 rounded-lg bg-red-50 dark:bg-red-950/30">
					<p class="text-red-600 dark:text-red-400 text-sm font-medium">
						Error loading membership data
					</p>
					<p class="text-red-600 dark:text-red-400 text-sm mt-1">
						{error}
					</p>
				</div>
			{:else}
				<!-- Current Plan -->
				<div class="space-y-4">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-3">
							<PlanBadge 
								planType={currentPlan}
								status={subscription?.status}
								size="md"
								showStatus={true}
							/>
							<div>
								<h3 class="font-semibold">{subscriptionStore.getPlanDisplayName()}</h3>
								{#if subscription && getRenewalText()}
									<p class="text-sm text-slate-600 dark:text-slate-300">
										{getRenewalText()}
									</p>
								{/if}
							</div>
						</div>
						
						{#if currentPlan !== 'enterprise'}
							{#if currentPlan === 'free'}
								<CheckoutButton
									planType="pro"
									buttonText="Upgrade Plan"
									buttonClass="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded cursor-pointer border-none"
								/>
							{:else}
								<Button variant="outline" onclick={handleManageSubscription}>
									Manage Subscription
								</Button>
							{/if}
						{/if}
					</div>

					<!-- Subscription Details -->
					{#if subscription}
						<div class="grid grid-cols-2 gap-4 p-4 bg-slate-50 dark:bg-slate-900 rounded-lg">
							<div>
								<p class="text-sm font-medium text-slate-900 dark:text-slate-100">Status</p>
								<p class="text-sm text-slate-600 dark:text-slate-300 capitalize">
									{subscription.status}
								</p>
							</div>
							<div>
								<p class="text-sm font-medium text-slate-900 dark:text-slate-100">
									{isTrialing ? 'Trial Ends' : 'Next Billing'}
								</p>
								<p class="text-sm text-slate-600 dark:text-slate-300">
									{formatDate(subscription.current_period_end)}
								</p>
							</div>
						</div>
					{/if}
				</div>

				<Separator />

				<!-- Usage -->
				<div class="space-y-4">
					<h3 class="font-semibold">Token Usage</h3>
					<UsageIndicator 
						usage={usageLimits}
						showNumbers={true}
						showPercentage={true}
					/>
				</div>

				<!-- Plan Features -->
				{#if planFeatures}
					<Separator />
					<div class="space-y-4">
						<h3 class="font-semibold">Plan Features</h3>
						<div class="space-y-2">
							{#if planFeatures.monthly_token_limit}
								<div class="flex items-center gap-2">
									<div class="w-2 h-2 bg-blue-500 rounded-full"></div>
									<span class="text-sm">{planFeatures.monthly_token_limit.toLocaleString()} tokens per month</span>
								</div>
							{:else}
								<div class="flex items-center gap-2">
									<div class="w-2 h-2 bg-green-500 rounded-full"></div>
									<span class="text-sm">Unlimited tokens</span>
								</div>
							{/if}
							
							{#if planFeatures.characters_limit}
								<div class="flex items-center gap-2">
									<div class="w-2 h-2 bg-blue-500 rounded-full"></div>
									<span class="text-sm">{planFeatures.characters_limit} character{planFeatures.characters_limit === 1 ? '' : 's'}</span>
								</div>
							{/if}
							
							{#if planFeatures.lorebooks_limit}
								<div class="flex items-center gap-2">
									<div class="w-2 h-2 bg-blue-500 rounded-full"></div>
									<span class="text-sm">{planFeatures.lorebooks_limit} lorebook{planFeatures.lorebooks_limit === 1 ? '' : 's'}</span>
								</div>
							{/if}
							
							{#if planFeatures.features}
								{#each Object.entries(planFeatures.features) as [key, value]}
									{#if value === true}
										<div class="flex items-center gap-2">
											<div class="w-2 h-2 bg-green-500 rounded-full"></div>
											<span class="text-sm">{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
										</div>
									{/if}
								{/each}
							{/if}
						</div>
					</div>
				{/if}

				<!-- Upgrade Options -->
				{#if currentPlan === 'free'}
					<Separator />
					<div class="space-y-4">
						<h3 class="font-semibold">Upgrade Options</h3>
						<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
							<div class="p-4 border rounded-lg">
								<div class="flex items-center gap-2 mb-2">
									<PlanBadge planType="pro" size="sm" />
									<span class="font-medium">Pro Plan</span>
								</div>
								<p class="text-sm text-slate-600 dark:text-slate-300 mb-3">
									Perfect for regular users with higher token needs
								</p>
								<CheckoutButton
									planType="pro"
									buttonText="Upgrade to Pro"
									buttonClass="w-full"
								/>
							</div>
							
							<div class="p-4 border rounded-lg">
								<div class="flex items-center gap-2 mb-2">
									<PlanBadge planType="enterprise" size="sm" />
									<span class="font-medium">Enterprise Plan</span>
								</div>
								<p class="text-sm text-slate-600 dark:text-slate-300 mb-3">
									Unlimited usage with priority support
								</p>
								<CheckoutButton
									planType="enterprise"
									buttonText="Upgrade to Enterprise"
									buttonClass="w-full"
								/>
							</div>
						</div>
					</div>
				{/if}
			{/if}
		</CardContent>
	</Card>
{:else}
	<!-- Fallback when payments are disabled -->
	<Card class="w-full">
		<CardHeader>
			<CardTitle>Membership</CardTitle>
		</CardHeader>
		<CardContent>
			<div class="flex items-center gap-3">
				<PlanBadge planType="free" size="md" />
				<div>
					<p class="font-semibold">Free Plan</p>
					<p class="text-sm text-slate-600 dark:text-slate-300">
						Payments are currently disabled
					</p>
				</div>
			</div>
		</CardContent>
	</Card>
{/if}