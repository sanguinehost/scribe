<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Separator } from '$lib/components/ui/separator';
	import { CreditCard, Zap, MessageCircle, Layers, Shield } from 'lucide-svelte';
	import PlanBadge from './PlanBadge.svelte';
	import DailyMessageUsage from './DailyMessageUsage.svelte';
	import MonthlyTokenUsage from './MonthlyTokenUsage.svelte';
	import { CheckoutButton } from '$lib/components/payment';
	import { CreditBalance, PurchaseCreditsDialog } from '$lib/components/credits';

	// Reactive subscription data
	let subscription = $derived(subscriptionStore.subscription);
	let planFeatures = $derived(subscriptionStore.planFeatures);
	let usageLimits = $derived(subscriptionStore.usageLimits);
	let customerPortalUrl = $derived(subscriptionStore.customerPortalUrl);
	let loading = $derived(subscriptionStore.loading);
	let error = $derived(subscriptionStore.error);
	let currentPlan = $derived(subscriptionStore.currentPlan);
	let _isSubscribed = $derived(subscriptionStore.isSubscribed);
	let isTrialing = $derived(subscriptionStore.isTrialing);
	let isCancelledTrial = $derived(subscriptionStore.isCancelledTrial);
	let isExpiredTrial = $derived(subscriptionStore.isExpiredTrial);
	let daysUntilRenewal = $derived(subscriptionStore.daysUntilRenewal);
	let isFreeUser = $derived(subscriptionStore.isFreeUser);

	// Credit data - creditStore is a store, not a plain object
	// We'll use the CreditBalance component which handles its own store subscription

	// Daily usage data from subscription store
	let dailyMessageCount = $derived(subscriptionStore.dailyMessageCount);
	let isThrottled = $derived(subscriptionStore.isThrottled);
	let throttleDelay = $derived(subscriptionStore.throttleDelay);

	// Purchase credits dialog state
	let showPurchaseDialog = $state(false);

	function handlePurchaseCreditsClick() {
		showPurchaseDialog = true;
	}

	function _handleViewPricing() {
		// Instead of navigating to pricing page, we'll show upgrade options directly
		// This function is kept for backward compatibility but could be removed
		console.log('View pricing clicked - showing upgrade options directly');
	}

	function handleManageSubscription() {
		if (!subscription) {
			toast.error('No active subscription found.');
			return;
		}

		if (!customerPortalUrl) {
			toast.error('Unable to access subscription management. Please try again later.');
			console.warn('No customer portal URL available for subscription:', subscription.id);
			return;
		}

		// Open Paddle customer portal in new tab
		try {
			window.open(customerPortalUrl, '_blank', 'noopener,noreferrer');
			toast.success('Opening subscription management portal...');
		} catch (error) {
			console.error('Failed to open customer portal:', error);
			toast.error('Failed to open subscription management portal.');
		}
	}

	function getRenewalText(): string {
		if (!subscription) return '';

		// Handle expired trials first
		const isExpiredTrial = subscriptionStore.isExpiredTrial;
		if (isExpiredTrial) {
			return 'Trial expired - Back to Free Plan';
		}

		// Handle cancelled paid subscriptions (converted from trial, then cancelled)
		const isCancelledPaid = subscriptionStore.isCancelledPaidSubscription;
		if (isCancelledPaid) {
			return `Subscription expires in ${daysUntilRenewal} days`;
		}

		// Handle cancelled trials specifically (never converted to paid)
		if (isCancelledTrial) {
			return `Trial expires in ${daysUntilRenewal} days`;
		}

		if (isTrialing) {
			// For active trials
			return `Trial ends in ${daysUntilRenewal} days`;
		}

		// For non-trial subscriptions
		if (subscription.cancel_at_period_end) {
			return `Subscription expires in ${daysUntilRenewal} days`;
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
				<div class="animate-pulse space-y-4">
					<div class="h-8 rounded bg-slate-200 dark:bg-slate-700"></div>
					<div class="h-20 rounded bg-slate-200 dark:bg-slate-700"></div>
					<div class="h-16 rounded bg-slate-200 dark:bg-slate-700"></div>
				</div>
			{:else if error}
				<div
					class="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-950/30"
				>
					<p class="text-sm font-medium text-red-600 dark:text-red-400">
						Error loading membership data
					</p>
					<p class="mt-1 text-sm text-red-600 dark:text-red-400">
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
								_size="md"
								showStatus={true}
							/>
							<div>
								<h3 class="font-semibold">{subscriptionStore.getPlanDisplayName()}</h3>
								{#if !isFreeUser && subscription && getRenewalText()}
									<p class="text-sm text-slate-600 dark:text-slate-300">
										{getRenewalText()}
									</p>
								{:else if isFreeUser}
									<p class="text-sm text-slate-600 dark:text-slate-300">No subscription active</p>
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
								<ButtonComponent variant="outline" onclick={handleManageSubscription}>
									Manage Subscription
								</ButtonComponent>
							{/if}
						{/if}
					</div>

					<!-- Subscription Details -->
					{#if !isFreeUser && subscription}
						<div class="grid grid-cols-2 gap-4 rounded-lg bg-slate-50 p-4 dark:bg-slate-900">
							<div>
								<p class="text-sm font-medium text-slate-900 dark:text-slate-100">Status</p>
								<p class="text-sm text-slate-600 dark:text-slate-300">
									{isExpiredTrial
										? 'Trial Expired'
										: isCancelledTrial
											? subscriptionStore.getStatusText()
											: subscriptionStore.formatStatusDisplay(subscription.status)}
								</p>
							</div>
							<div>
								<p class="text-sm font-medium text-slate-900 dark:text-slate-100">
									{isExpiredTrial
										? 'Trial Expired'
										: isCancelledTrial
											? 'Trial Expires'
											: isTrialing
												? 'Trial Ends'
												: 'Next Billing'}
								</p>
								<p class="text-sm text-slate-600 dark:text-slate-300">
									{formatDate(
										// For cancelled paid subscriptions, use current_period_end
										// For trials (active, cancelled, or expired) that never paid, use trial_end
										subscription.has_ever_paid === true
											? subscription.current_period_end
											: (isTrialing || isCancelledTrial || isExpiredTrial) && subscription.trial_end
												? subscription.trial_end
												: subscription.current_period_end
									)}
								</p>
							</div>
						</div>
					{:else if isFreeUser}
						<!-- Free User Information -->
						<div class="rounded-lg bg-blue-50 p-4 dark:bg-blue-950/30">
							<div class="flex items-start gap-3">
								<div class="flex-shrink-0">
									<svg
										class="h-5 w-5 text-blue-600 dark:text-blue-400"
										fill="currentColor"
										viewBox="0 0 20 20"
									>
										<path
											fill-rule="evenodd"
											d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
											clip-rule="evenodd"
										/>
									</svg>
								</div>
								<div>
									<p class="text-sm font-medium text-blue-900 dark:text-blue-200">
										Free Plan Active
									</p>
									<p class="mt-1 text-sm text-blue-700 dark:text-blue-300">
										You're currently using the free tier. Upgrade to unlock additional features and
										higher limits.
									</p>
								</div>
							</div>
						</div>
					{/if}
				</div>

				<Separator />

				<!-- Daily Messages -->
				<div class="space-y-4">
					<h3 class="flex items-center gap-2 font-semibold">
						<MessageCircle size={16} />
						Daily Activity
					</h3>
					<DailyMessageUsage
						messageCount={dailyMessageCount}
						planType={currentPlan}
						{isThrottled}
						{throttleDelay}
						_size="md"
					/>
				</div>

				<Separator />

				<!-- Monthly Token Usage -->
				<div class="space-y-4">
					<h3 class="flex items-center gap-2 font-semibold">
						<Zap size={16} />
						Monthly Token Usage
					</h3>
					<div class="rounded-lg bg-slate-50 p-4 dark:bg-slate-900">
						<MonthlyTokenUsage {usageLimits} size="md" showNumbers={true} showPeriod={true} />
						{#if usageLimits && !usageLimits.is_unlimited}
							<div class="mt-3 text-xs text-slate-500 dark:text-slate-400">
								Token usage is tracked for billing and administrative purposes. Daily message limits
								are used for user throttling.
							</div>
						{/if}
					</div>
				</div>

				<Separator />

				<!-- Credits -->
				<div class="space-y-4">
					<h3 class="flex items-center gap-2 font-semibold">
						<Zap size={16} />
						Credits
					</h3>
					<CreditBalance showPurchaseButton={true} onPurchaseClick={handlePurchaseCreditsClick} />
				</div>

				<!-- Plan Features -->
				{#if planFeatures}
					<Separator />
					<div class="space-y-4">
						<h3 class="font-semibold">Plan Features</h3>
						<div class="grid grid-cols-1 gap-3 md:grid-cols-2">
							<!-- Daily Messages -->
							<div class="flex items-start gap-2">
								<MessageCircle size={14} class="mt-0.5 text-blue-500" />
								<div>
									<span class="text-sm font-medium">
										{currentPlan === 'free' ? '20' : currentPlan === 'basic' ? '100' : '200'} messages/day
									</span>
									<span class="block text-xs text-slate-500 dark:text-slate-400">
										{currentPlan === 'free' ? 'Hard limit' : 'Soft limit'}
									</span>
								</div>
							</div>

							<!-- Included Credits -->
							<div class="flex items-start gap-2">
								<Zap size={14} class="mt-0.5 text-yellow-500" />
								<div>
									<span class="text-sm font-medium">
										{currentPlan === 'free' ? '25' : currentPlan === 'basic' ? '250' : '800'} credits
									</span>
									<span class="block text-xs text-slate-500 dark:text-slate-400">
										{currentPlan === 'free' ? 'One-time bonus' : 'Monthly allocation'}
									</span>
								</div>
							</div>

							<!-- Context Limit -->
							<div class="flex items-start gap-2">
								<Layers size={14} class="mt-0.5 text-purple-500" />
								<div>
									<span class="text-sm font-medium">
										{currentPlan === 'free' ? '32k' : currentPlan === 'basic' ? '64k' : '200k'} context
									</span>
									<span class="block text-xs text-slate-500 dark:text-slate-400">
										Token limit
									</span>
								</div>
							</div>

							<!-- Characters & Lorebooks -->
							{#if currentPlan !== 'free'}
								<div class="flex items-start gap-2">
									<Shield size={14} class="mt-0.5 text-green-500" />
									<div>
										<span class="text-sm font-medium">
											{currentPlan === 'basic' ? '50 characters' : 'Unlimited characters'}
										</span>
										<span class="block text-xs text-slate-500 dark:text-slate-400">
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
						<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
							<div class="rounded-lg border p-4">
								<div class="mb-2 flex items-center gap-2">
									<PlanBadge planType="basic" _size="sm" />
									<span class="font-medium">Basic Plan</span>
								</div>
								<p class="mb-3 text-sm text-slate-600 dark:text-slate-300">
									For serious character AI enthusiasts and creators
								</p>
								<CheckoutButton
									planType="basic"
									buttonText="Upgrade to Basic"
									buttonClass="w-full"
								/>
							</div>

							<div class="rounded-lg border p-4">
								<div class="mb-2 flex items-center gap-2">
									<PlanBadge planType="premium" _size="sm" />
									<span class="font-medium">Premium Plan</span>
								</div>
								<p class="mb-3 text-sm text-slate-600 dark:text-slate-300">
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
				<PlanBadge planType="free" _size="md" />
				<div>
					<p class="font-semibold">Free Plan</p>
					<p class="text-sm text-slate-600 dark:text-slate-300">Payments are currently disabled</p>
				</div>
			</div>
		</CardContent>
	</Card>

	<!-- Purchase Credits Dialog -->
	<PurchaseCreditsDialog bind:open={showPurchaseDialog} />
{/if}
