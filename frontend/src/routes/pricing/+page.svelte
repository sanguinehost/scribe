<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { apiClient } from '$lib/api';
	import SubscriptionCheckout from '$lib/components/subscriptions/SubscriptionCheckout.svelte';
	import { Alert, AlertDescription } from '$lib/components/ui/alert';
	import { Loader, AlertCircle } from 'lucide-svelte';
	import type { PlanFeatures, PlanType } from '$lib/types/payment';

	// Component state
	let plans: PlanFeatures[] = $state([]);
	let currentPlan: PlanType = $state('free');
	let isLoading = $state(false);
	let error: string | null = $state(null);

	// Load plans and current subscription
	onMount(async () => {
		if (!ENABLE_PAYMENTS) return;

		isLoading = true;
		error = null;

		try {
			// Load available plans
			const plansResult = await apiClient.getPlans();
			if (plansResult.isOk()) {
				plans = plansResult.value.plans;
				currentPlan = plansResult.value.current_plan || 'free';
			} else {
				error = plansResult.error.message || 'Failed to load subscription plans';
			}
		} catch (err) {
			error = 'Failed to load subscription plans';
			console.error('Error loading plans:', err);
		} finally {
			isLoading = false;
		}
	});

	async function handleCreateSubscription(planType: PlanType, billingCycle: 'monthly' | 'yearly') {
		if (!ENABLE_PAYMENTS) return;

		try {
			const result = await apiClient.createSubscription({
				plan_type: planType,
				billing_period: billingCycle
			});

			if (result.isOk()) {
				// Redirect to Paddle checkout
				window.location.href = result.value.checkout_url;
			} else {
				throw new Error(result.error.message || 'Failed to create subscription');
			}
		} catch (err) {
			const errorMessage = err instanceof Error ? err.message : 'Failed to create subscription';
			error = errorMessage;
			throw err; // Re-throw so SubscriptionCheckout can handle it
		}
	}

	function handlePlanSelected(
		event: CustomEvent<{ planType: PlanType; billingCycle: 'monthly' | 'yearly' }>
	) {
		console.log('Plan selected:', event.detail);
	}

	function handleCheckoutStarted(
		event: CustomEvent<{ planType: PlanType; billingCycle: 'monthly' | 'yearly' }>
	) {
		console.log('Checkout started:', event.detail);
	}

	function handleSubscriptionCreated(
		event: CustomEvent<{ planType: PlanType; billingCycle: 'monthly' | 'yearly' }>
	) {
		// For free plan, just redirect to app
		if (event.detail.planType === 'free') {
			goto('/');
		}
	}
</script>

<svelte:head>
	<title>Pricing - Sanguine Scribe</title>
	<meta name="description" content="Choose the perfect plan for your character AI conversations" />
</svelte:head>

<div
	class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800"
>
	<div class="container mx-auto px-4 py-12">
		{#if !ENABLE_PAYMENTS}
			<!-- Payments disabled -->
			<div class="space-y-6 text-center">
				<h1 class="text-4xl font-bold text-slate-900 dark:text-slate-100">Pricing</h1>
				<Alert variant="destructive" class="mx-auto max-w-2xl">
					<AlertCircle class="h-4 w-4" />
					<AlertDescription>
						Payment features are currently disabled. Please try again later or contact support.
					</AlertDescription>
				</Alert>
			</div>
		{:else if isLoading}
			<!-- Loading state -->
			<div class="space-y-6 text-center">
				<h1 class="text-4xl font-bold text-slate-900 dark:text-slate-100">Loading Plans...</h1>
				<div class="flex justify-center">
					<Loader class="h-8 w-8 animate-spin" />
				</div>
			</div>
		{:else if error}
			<!-- Error state -->
			<div class="space-y-6 text-center">
				<h1 class="text-4xl font-bold text-slate-900 dark:text-slate-100">Pricing</h1>
				<Alert variant="destructive" class="mx-auto max-w-2xl">
					<AlertCircle class="h-4 w-4" />
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			</div>
		{:else}
			<!-- Main subscription checkout -->
			<SubscriptionCheckout
				{plans}
				{currentPlan}
				{isLoading}
				{error}
				onCreateSubscription={handleCreateSubscription}
				on:planSelected={handlePlanSelected}
				on:checkoutStarted={handleCheckoutStarted}
				on:subscriptionCreated={handleSubscriptionCreated}
			/>

			<!-- FAQ Section -->
			<div class="mx-auto mt-20 max-w-4xl">
				<h2 class="mb-12 text-center text-3xl font-bold text-slate-900 dark:text-slate-100">
					Frequently Asked Questions
				</h2>

				<div class="space-y-8">
					<div class="rounded-lg bg-white p-6 shadow-lg dark:bg-slate-800">
						<h3 class="mb-2 text-lg font-semibold text-slate-900 dark:text-slate-100">
							What are credits?
						</h3>
						<p class="text-slate-600 dark:text-slate-300">
							Credits are used to access premium AI models. Each model has different credit costs
							based on its capabilities. Your monthly plan includes credits, and you can purchase
							additional credits if needed.
						</p>
					</div>

					<div class="rounded-lg bg-white p-6 shadow-lg dark:bg-slate-800">
						<h3 class="mb-2 text-lg font-semibold text-slate-900 dark:text-slate-100">
							Can I change plans at any time?
						</h3>
						<p class="text-slate-600 dark:text-slate-300">
							Yes! You can upgrade or downgrade your plan at any time. Changes take effect at the
							next billing cycle, and we'll prorate any differences. Unused credits roll over with
							paid plans.
						</p>
					</div>

					<div class="rounded-lg bg-white p-6 shadow-lg dark:bg-slate-800">
						<h3 class="mb-2 text-lg font-semibold text-slate-900 dark:text-slate-100">
							What's the difference between annual and monthly billing?
						</h3>
						<p class="text-slate-600 dark:text-slate-300">
							Annual billing saves you 17% compared to monthly billing. You get the same features
							and credits, just at a discounted rate when you pay yearly.
						</p>
					</div>

					<div class="rounded-lg bg-white p-6 shadow-lg dark:bg-slate-800">
						<h3 class="mb-2 text-lg font-semibold text-slate-900 dark:text-slate-100">
							What payment methods do you accept?
						</h3>
						<p class="text-slate-600 dark:text-slate-300">
							We accept all major credit cards, PayPal, and other payment methods through our secure
							payment processor Paddle. All transactions are encrypted and secure.
						</p>
					</div>

					<div class="rounded-lg bg-white p-6 shadow-lg dark:bg-slate-800">
						<h3 class="mb-2 text-lg font-semibold text-slate-900 dark:text-slate-100">
							Can I cancel anytime?
						</h3>
						<p class="text-slate-600 dark:text-slate-300">
							Absolutely! All plans can be cancelled anytime with no cancellation fees. Your
							subscription will remain active until the end of your current billing period.
						</p>
					</div>
				</div>
			</div>
		{/if}
	</div>
</div>
