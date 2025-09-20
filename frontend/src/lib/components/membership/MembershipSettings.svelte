<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Separator } from '$lib/components/ui/separator';
	import { CreditCard, Zap, MessageCircle, Layers, Shield } from 'lucide-svelte';
	import PlanBadge from './PlanBadge.svelte';
	import DailyMessageUsage from './DailyMessageUsage.svelte';
	import { CheckoutButton } from '$lib/components/payment';
	import { CreditBalance } from '$lib/components/credits';

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

	// Credit data - creditStore is a store, not a plain object
	// We'll use the CreditBalance component which handles its own store subscription

	// Daily usage data from subscription store
	$: dailyMessageCount = subscriptionStore.dailyMessageCount;
	$: isThrottled = subscriptionStore.isThrottled;
	$: throttleDelay = subscriptionStore.throttleDelay;

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
				<CreditCard size={20} />
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
						
						{#if currentPlan !== 'premium'}
							{#if currentPlan === 'free'}
								<CheckoutButton
									planType="basic"
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

				<!-- Daily Messages -->
				<div class="space-y-4">
					<h3 class="font-semibold flex items-center gap-2">
						<MessageCircle size={16} />
						Daily Activity
					</h3>
					<DailyMessageUsage
						messageCount={dailyMessageCount}
						planType={currentPlan}
						isThrottled={isThrottled}
						throttleDelay={throttleDelay}
						size="md"
					/>
				</div>

				<Separator />

				<!-- Credits -->
				<div class="space-y-4">
					<h3 class="font-semibold flex items-center gap-2">
						<Zap size={16} />
						Credits
					</h3>
					<CreditBalance showPurchaseButton={true} />
				</div>

				<!-- Plan Features -->
				{#if planFeatures}
					<Separator />
					<div class="space-y-4">
						<h3 class="font-semibold">Plan Features</h3>
						<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
							<!-- Daily Messages -->
							<div class="flex items-start gap-2">
								<MessageCircle size={14} class="text-blue-500 mt-0.5" />
								<div>
									<span class="text-sm font-medium">
										{currentPlan === 'free' ? '20' : currentPlan === 'basic' ? '100' : '200'} messages/day
									</span>
									<span class="text-xs text-slate-500 dark:text-slate-400 block">
										{currentPlan === 'free' ? 'Hard limit' : 'Soft limit'}
									</span>
								</div>
							</div>

							<!-- Included Credits -->
							<div class="flex items-start gap-2">
								<Zap size={14} class="text-yellow-500 mt-0.5" />
								<div>
									<span class="text-sm font-medium">
										{currentPlan === 'free' ? '25' : currentPlan === 'basic' ? '250' : '800'} credits
									</span>
									<span class="text-xs text-slate-500 dark:text-slate-400 block">
										{currentPlan === 'free' ? 'One-time bonus' : 'Monthly allocation'}
									</span>
								</div>
							</div>

							<!-- Context Limit -->
							<div class="flex items-start gap-2">
								<Layers size={14} class="text-purple-500 mt-0.5" />
								<div>
									<span class="text-sm font-medium">
										{currentPlan === 'free' ? '32k' : currentPlan === 'basic' ? '64k' : '200k'} context
									</span>
									<span class="text-xs text-slate-500 dark:text-slate-400 block">
										Token limit
									</span>
								</div>
							</div>

							<!-- Characters & Lorebooks -->
							{#if currentPlan !== 'free'}
								<div class="flex items-start gap-2">
									<Shield size={14} class="text-green-500 mt-0.5" />
									<div>
										<span class="text-sm font-medium">
											{currentPlan === 'basic' ? '50 characters' : 'Unlimited characters'}
										</span>
										<span class="text-xs text-slate-500 dark:text-slate-400 block">
											Character slots
										</span>
									</div>
								</div>
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
									<PlanBadge planType="basic" size="sm" />
									<span class="font-medium">Basic Plan</span>
								</div>
								<p class="text-sm text-slate-600 dark:text-slate-300 mb-3">
									For serious character AI enthusiasts and creators
								</p>
								<CheckoutButton
									planType="basic"
									buttonText="Upgrade to Basic"
									buttonClass="w-full"
								/>
							</div>
							
							<div class="p-4 border rounded-lg">
								<div class="flex items-center gap-2 mb-2">
									<PlanBadge planType="premium" size="sm" />
									<span class="font-medium">Premium Plan</span>
								</div>
								<p class="text-sm text-slate-600 dark:text-slate-300 mb-3">
									Professional roleplay & storytelling platform
								</p>
								<CheckoutButton
									planType="premium"
									buttonText="Upgrade to Premium"
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