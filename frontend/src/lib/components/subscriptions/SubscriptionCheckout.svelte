<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button } from '$lib/components/ui/button';
	import { Alert, AlertDescription } from '$lib/components/ui/alert';
	import { Loader, ArrowLeft, ExternalLink, AlertCircle } from 'lucide-svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import PlanSelector from './PlanSelector.svelte';
	import OrderSummary from './OrderSummary.svelte';
	import type { PlanFeatures, PlanType, OrderPreview } from '$lib/types/payment';

	interface Props {
		plans: PlanFeatures[];
		currentPlan?: PlanType;
		isLoading?: boolean;
		error?: string | null;
		onCreateSubscription?: (planType: PlanType, billingCycle: 'monthly' | 'yearly') => Promise<void>;
		onBack?: () => void;
		showBackButton?: boolean;
	}

	let {
		plans = [],
		currentPlan = 'free',
		isLoading = false,
		error = null,
		onCreateSubscription = async () => {},
		onBack = () => {},
		showBackButton = false
	}: Props = $props();

	const dispatch = createEventDispatcher();

	// Component state
	let checkoutStep: 'select' | 'review' | 'processing' = $state('select');
	let selectedPlan: PlanType | null = $state(null);
	let billingCycle: 'monthly' | 'yearly' = $state('monthly');
	let orderPreview: OrderPreview | null = $state(null);
	let checkoutError: string | null = $state(null);

	// Get selected plan features
	const selectedPlanFeatures = $derived.by(() => {
		if (!selectedPlan) return null;
		return plans.find(p => p.plan_type === selectedPlan) || null;
	});

	function handlePlanSelect(planType: PlanType, cycle: 'monthly' | 'yearly') {
		selectedPlan = planType;
		billingCycle = cycle;
		checkoutError = null;

		if (planType === 'free') {
			// Free plan doesn't need checkout, emit event directly
			dispatch('subscriptionCreated', { planType, billingCycle: 'monthly' });
			return;
		}

		// Move to review step for paid plans
		checkoutStep = 'review';
		generateOrderPreview();

		dispatch('planSelected', { planType, billingCycle: cycle });
	}

	function handleBillingCycleChange(cycle: 'monthly' | 'yearly') {
		billingCycle = cycle;
		if (checkoutStep === 'review') {
			generateOrderPreview();
		}
	}

	function generateOrderPreview() {
		if (!selectedPlanFeatures) return;

		const isYearly = billingCycle === 'yearly';
		const amount = isYearly ? selectedPlanFeatures.price_yearly! : selectedPlanFeatures.price_monthly;

		orderPreview = {
			plan_name: selectedPlanFeatures.display_name,
			plan_type: selectedPlan!,
			billing_period: billingCycle,
			line_items: [{
				description: `${selectedPlanFeatures.display_name} Plan`,
				billing_period: billingCycle === 'monthly' ? 'Monthly billing' : 'Annual billing',
				amount,
				currency: 'USD'
			}],
			subtotal: amount,
			tax_amount: 0, // Could be calculated server-side
			total_amount: amount,
			currency: 'USD',
			next_billing_date: new Date(Date.now() + (isYearly ? 365 : 30) * 24 * 60 * 60 * 1000).toISOString(),
			savings_message: isYearly ? selectedPlanFeatures.billing_features?.yearly?.savings_message : undefined,
			cancellation_policy: 'Cancel anytime. No cancellation fees.'
		};
	}

	function handleBackToPlans() {
		checkoutStep = 'select';
		selectedPlan = null;
		orderPreview = null;
		checkoutError = null;
	}

	async function handleProceedToCheckout() {
		if (!selectedPlan || !selectedPlanFeatures) return;

		checkoutStep = 'processing';
		checkoutError = null;

		try {
			await onCreateSubscription(selectedPlan, billingCycle);
			dispatch('checkoutStarted', { planType: selectedPlan, billingCycle });
		} catch (err) {
			checkoutError = err instanceof Error ? err.message : 'Failed to start checkout';
			checkoutStep = 'review';
		}
	}

	// Reset state when error prop changes
	$effect(() => {
		if (error) {
			checkoutError = error;
			checkoutStep = selectedPlan ? 'review' : 'select';
		}
	});
</script>

{#if ENABLE_PAYMENTS}
<div class="w-full max-w-7xl mx-auto">
	{#if checkoutStep === 'select'}
		<!-- Plan Selection Step -->
		<div class="space-y-8">
			{#if showBackButton}
				<Button variant="ghost" on:click={onBack} class="mb-4">
					<ArrowLeft class="w-4 h-4 mr-2" />
					Back
				</Button>
			{/if}

			<div class="text-center space-y-4">
				<h1 class="text-3xl font-bold">Choose Your Plan</h1>
				<p class="text-muted-foreground text-lg max-w-2xl mx-auto">
					Unlock the full potential of character AI with our flexible subscription plans.
					Start your journey today.
				</p>
			</div>

			{#if error}
				<Alert variant="destructive" class="max-w-2xl mx-auto">
					<AlertCircle class="h-4 w-4" />
					<AlertDescription>{error}</AlertDescription>
				</Alert>
			{/if}

			<PlanSelector
				{plans}
				{currentPlan}
				{billingCycle}
				{isLoading}
				onPlanSelect={handlePlanSelect}
				onBillingCycleChange={handleBillingCycleChange}
			/>
		</div>

	{:else if checkoutStep === 'review'}
		<!-- Order Review Step -->
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
			<!-- Left Column: Order Details -->
			<div class="space-y-6">
				<div class="flex items-center gap-4">
					<Button variant="ghost" size="sm" on:click={handleBackToPlans}>
						<ArrowLeft class="w-4 h-4 mr-2" />
						Back to plans
					</Button>
				</div>

				<div class="space-y-4">
					<h2 class="text-2xl font-bold">Review Your Order</h2>
					<p class="text-muted-foreground">
						You're about to subscribe to the <strong>{selectedPlanFeatures?.display_name}</strong> plan.
						Review the details and proceed to secure checkout.
					</p>
				</div>

				{#if checkoutError}
					<Alert variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<AlertDescription>{checkoutError}</AlertDescription>
					</Alert>
				{/if}

				<!-- Plan Features Summary -->
				{#if selectedPlanFeatures}
					<div class="border rounded-lg p-4 space-y-3">
						<h3 class="font-semibold">What's included:</h3>
						<ul class="space-y-2 text-sm">
							<li>• {selectedPlanFeatures.limits.daily_messages} messages per day</li>
							<li>• {selectedPlanFeatures.limits.context_tokens / 1000}K context window</li>
							<li>• {selectedPlanFeatures.credits.included_monthly} credits per month</li>
							{#if selectedPlanFeatures.limits.chronicles_enabled}
								<li>• Chronicle system</li>
							{/if}
							{#if selectedPlanFeatures.limits.lorebooks_enabled}
								<li>• Lorebooks</li>
							{/if}
							{#if selectedPlanFeatures.features.priority_support}
								<li>• Priority support</li>
							{/if}
						</ul>
					</div>
				{/if}

				<!-- Checkout Actions -->
				<div class="space-y-4">
					<Button
						class="w-full"
						size="lg"
						disabled={isLoading}
						on:click={handleProceedToCheckout}
					>
						{#if isLoading}
							<Loader class="w-4 h-4 mr-2 animate-spin" />
							Processing...
						{:else}
							<ExternalLink class="w-4 h-4 mr-2" />
							Proceed to Secure Checkout
						{/if}
					</Button>

					<p class="text-xs text-muted-foreground text-center">
						You'll be redirected to our secure payment processor (Paddle) to complete your purchase.
						Your subscription will be activated immediately after payment confirmation.
					</p>
				</div>
			</div>

			<!-- Right Column: Order Summary -->
			<div class="lg:sticky lg:top-8">
				<OrderSummary
					{orderPreview}
					planFeatures={selectedPlanFeatures}
					{isLoading}
				/>
			</div>
		</div>

	{:else if checkoutStep === 'processing'}
		<!-- Processing Step -->
		<div class="text-center space-y-6 py-12">
			<div class="w-16 h-16 mx-auto">
				<Loader class="w-full h-full animate-spin text-primary" />
			</div>
			<div class="space-y-2">
				<h2 class="text-2xl font-bold">Setting up your checkout...</h2>
				<p class="text-muted-foreground">
					Please wait while we prepare your secure payment session.
				</p>
			</div>
		</div>
	{/if}
</div>
{/if}