<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { apiClient as _apiClient } from '$lib/api';
	import { PUBLIC_PADDLE_CLIENT_SIDE_TOKEN } from '$env/static/public';
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription
	} from '$lib/components/ui/dialog';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Card, CardContent } from '$lib/components/ui/card';
	import { Badge as BadgeComponent } from '$lib/components/ui/badge';
	import type { PlanType } from '$lib/types';

	// Props
	export let open: boolean = false;
	export let initialPlan: PlanType = 'basic';

	// State
	let selectedPlan: PlanType = initialPlan;
	let selectedBilling: 'monthly' | 'yearly' = 'monthly';
	let checkoutLoading = false;
	let checkoutError: string | null = null;

	const dispatch = createEventDispatcher<{
		close: void;
		'checkout-start': { planType: PlanType; billing: 'monthly' | 'yearly' };
		'checkout-complete': { transactionId: string };
	}>();

	// Plan details - matching backend configuration
	const plans = {
		basic: {
			name: 'Basic',
			description: 'For serious character AI enthusiasts and creators',
			monthly: {
				price: 10,
				priceId: 'pri_01k4qbyetvn495nzv9nkqhxz02',
				display: '$10/month'
			},
			yearly: {
				price: 100,
				priceId: 'pri_01k5ejs7h9zmw4d888r3pjjqna',
				display: '$100/year',
				monthlyEquivalent: '$8.33/month',
				savings: 'Save $20 per year'
			},
			features: [
				'100 daily messages (soft limit)',
				'250 included credits/month',
				'Chronicles & Lorebooks enabled',
				'Up to 50 characters',
				'Priority support'
			]
		},
		premium: {
			name: 'Premium',
			description: 'Professional roleplay & storytelling platform',
			monthly: {
				price: 25,
				priceId: 'pri_01k5ej7wzvpcj6j65vcbpam6t4',
				display: '$25/month'
			},
			yearly: {
				price: 250,
				priceId: 'pri_01k5ejva0cwqzbtgzd2c9qk0d4',
				display: '$250/year',
				monthlyEquivalent: '$20.83/month',
				savings: 'Save $50 per year'
			},
			features: [
				'200 daily messages (soft limit)',
				'800 included credits/month',
				'Unlimited characters & lorebooks',
				'API access',
				'Priority queue & beta features'
			]
		},
		pro: {
			name: 'Premium',
			description: 'Professional roleplay & storytelling platform',
			monthly: {
				price: 25,
				priceId: 'pri_01k5ej7wzvpcj6j65vcbpam6t4',
				display: '$25/month'
			},
			yearly: {
				price: 250,
				priceId: 'pri_01k5ejva0cwqzbtgzd2c9qk0d4',
				display: '$250/year',
				monthlyEquivalent: '$20.83/month',
				savings: 'Save $50 per year'
			},
			features: [
				'200 daily messages (soft limit)',
				'800 included credits/month',
				'Unlimited characters & lorebooks',
				'API access',
				'Priority queue & beta features'
			]
		}
	};

	// Get current plan details - handle free plan which isn't purchasable
	$: currentPlan =
		selectedPlan === 'free' || selectedPlan === 'pro'
			? selectedPlan === 'pro'
				? plans.premium
				: null
			: plans[selectedPlan];
	$: currentPrice = currentPlan
		? selectedBilling === 'monthly'
			? currentPlan.monthly
			: currentPlan.yearly
		: null;

	async function handleCheckout() {
		if (!browser || !ENABLE_PAYMENTS || checkoutLoading) {
			return;
		}

		// Validate that we have a purchasable plan
		if (!currentPlan || !currentPrice) {
			checkoutError = 'Invalid plan selected. Please select a valid subscription plan.';
			return;
		}

		checkoutLoading = true;
		checkoutError = null;

		dispatch('checkout-start', { planType: selectedPlan, billing: selectedBilling });

		try {
			// Check if Paddle is loaded and initialized
			if (!window.Paddle) {
				throw new Error('Payment system not ready. Please refresh the page and try again.');
			}

			if (!window.Paddle.Checkout || typeof window.Paddle.Checkout.open !== 'function') {
				throw new Error(
					'Payment system not properly initialized. Please refresh the page and try again.'
				);
			}

			// Get price ID based on plan and billing period
			const priceId = currentPrice.priceId;

			// Detect theme for checkout
			const isDarkMode = document.documentElement.classList.contains('dark');
			const theme = isDarkMode ? 'dark' : 'light';

			// Log for debugging in sandbox
			console.log('Opening Paddle checkout with:', {
				plan: selectedPlan,
				billing: selectedBilling,
				priceId: priceId,
				theme: theme
			});

			// Note for sandbox testing
			if (PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.startsWith('test_')) {
				console.log(
					'🧪 Sandbox Mode - Use test cards: 4242 4242 4242 4242 (Visa) or 4000 0566 5566 5556 (Visa Debit)'
				);
			}

			// Open Paddle checkout with full configuration (now that environment is set correctly)
			console.log('🚀 Opening Paddle checkout with configuration:', {
				priceId: priceId,
				plan: selectedPlan,
				billing: selectedBilling,
				theme: theme,
				environment: PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.startsWith('test_') ? 'sandbox' : 'production'
			});

			// Close our dialog first to avoid z-index conflicts with Paddle overlay
			open = false;
			dispatch('close');

			window.Paddle.Checkout.open({
				// Items to purchase
				items: [
					{
						priceId: priceId,
						quantity: 1
					}
				],
				// UI settings for better UX
				settings: {
					displayMode: 'overlay', // Overlay mode for branded checkout
					theme: theme, // Match app theme
					locale: navigator.language?.substring(0, 2) || 'en',
					variant: 'one-page', // Simpler one-page checkout
					allowLogout: false, // Don't show logout option
					// Add success URL as backup (event callback is primary)
					successUrl: `${window.location.origin}/pay`
				},
				// Custom data for tracking and analytics
				customData: {
					plan: selectedPlan,
					billing: selectedBilling,
					source: 'checkout_overlay',
					version: '2.0'
				}
			});
		} catch (_error) {
			const errorMessage =
				_error instanceof Error ? _error.message : 'Payment initialization failed';
			console.error('❌ Checkout error details:', {
				error: _error,
				message: errorMessage,
				priceId: currentPrice?.priceId,
				plan: selectedPlan,
				billing: selectedBilling,
				paddleLoaded: !!window.Paddle,
				paddleCheckout: !!window.Paddle?.Checkout,
				token: PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.substring(0, 8) + '...'
			});
			checkoutError = errorMessage;
			checkoutLoading = false;
		}
	}

	function handleClose() {
		if (!checkoutLoading) {
			dispatch('close');
		}
	}

	function selectPlan(plan: PlanType) {
		selectedPlan = plan;
	}

	function _toggleBilling() {
		selectedBilling = selectedBilling === 'monthly' ? 'yearly' : 'monthly';
	}
</script>

{#if ENABLE_PAYMENTS}
	<Dialog bind:open onOpenChange={(_value) => !checkoutLoading && dispatch('close')}>
		<DialogContent class="max-w-4xl">
			<DialogHeader>
				<DialogTitle>Choose Your Plan</DialogTitle>
				<DialogDescription>
					Select the plan that best fits your needs. All plans include a 7-day free trial.
				</DialogDescription>
			</DialogHeader>

			<div class="space-y-6">
				<!-- Billing Toggle -->
				<div class="flex justify-center">
					<div class="inline-flex items-center gap-3 rounded-lg bg-muted p-1">
						<button
							class="rounded-md px-4 py-2 transition-all {selectedBilling === 'monthly'
								? 'bg-background shadow-sm'
								: ''}"
							onclick={() => (selectedBilling = 'monthly')}
							disabled={checkoutLoading}
						>
							Monthly
						</button>
						<button
							class="rounded-md px-4 py-2 transition-all {selectedBilling === 'yearly'
								? 'bg-background shadow-sm'
								: ''}"
							onclick={() => (selectedBilling = 'yearly')}
							disabled={checkoutLoading}
						>
							Yearly
							<BadgeComponent variant="secondary" class="ml-2">Save 17%</BadgeComponent>
						</button>
					</div>
				</div>

				<!-- Plan Cards -->
				<div class="grid gap-4 md:grid-cols-2">
					{#each Object.entries(plans) as [planKey, plan]}
						<Card
							class="cursor-pointer transition-all {selectedPlan === planKey
								? 'ring-2 ring-primary'
								: ''}"
							onclick={() => selectPlan(planKey as PlanType)}
						>
							<CardContent class="p-6">
								<div class="space-y-4">
									<div>
										<h3 class="text-xl font-semibold">{plan.name}</h3>
										<p class="text-sm text-muted-foreground">{plan.description}</p>
									</div>

									<div class="space-y-1">
										<div class="text-3xl font-bold">
											{selectedBilling === 'monthly' ? plan.monthly.display : plan.yearly.display}
										</div>
										{#if selectedBilling === 'yearly'}
											<div class="text-sm text-muted-foreground">
												{plan.yearly.monthlyEquivalent}
											</div>
											<div class="text-sm text-accent">
												{plan.yearly.savings}
											</div>
										{/if}
									</div>

									<ul class="space-y-2">
										{#each plan.features as feature}
											<li class="flex items-start gap-2">
												<svg
													class="mt-0.5 h-5 w-5 text-accent"
													fill="none"
													stroke="currentColor"
													viewBox="0 0 24 24"
												>
													<path
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="2"
														d="M5 13l4 4L19 7"
													/>
												</svg>
												<span class="text-sm">{feature}</span>
											</li>
										{/each}
									</ul>

									{#if selectedPlan === planKey}
										<div class="pt-2">
											<BadgeComponent variant="default">Selected</BadgeComponent>
										</div>
									{/if}
								</div>
							</CardContent>
						</Card>
					{/each}
				</div>

				<!-- Order Summary -->
				{#if currentPlan && currentPrice}
					<Card class="border-primary/30">
						<CardContent class="p-4">
							<div class="flex items-center justify-between">
								<div>
									<h4 class="font-semibold">Order Summary</h4>
									<p class="text-sm text-muted-foreground">
										{currentPlan.name} Plan - {selectedBilling === 'monthly' ? 'Monthly' : 'Yearly'}
										Billing
									</p>
								</div>
								<div class="text-right">
									<div class="text-2xl font-bold text-primary">
										{currentPrice.display}
									</div>
									{#if selectedBilling === 'yearly' && 'savings' in currentPrice}
										<div class="text-sm text-accent">
											{currentPrice.savings}
										</div>
									{/if}
								</div>
							</div>
						</CardContent>
					</Card>
				{/if}

				<!-- Sandbox Test Card Info -->
				{#if PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.startsWith('test_')}
					<Card class="border-accent/30 bg-accent/10">
						<CardContent class="p-4">
							<div class="flex items-start gap-3">
								<span class="text-lg">🧪</span>
								<div class="flex-1">
									<h5 class="text-sm font-semibold text-accent">Sandbox Mode - Test Cards</h5>
									<p class="mt-1 text-xs text-muted-foreground">
										Use these test card numbers for sandbox testing:
									</p>
									<ul class="mt-2 space-y-1 text-xs text-muted-foreground">
										<li>
											• <code class="rounded bg-muted px-1 py-0.5">4242 4242 4242 4242</code> - Visa
										</li>
										<li>
											• <code class="rounded bg-muted px-1 py-0.5">4000 0566 5566 5556</code> - Visa
											Debit
										</li>
										<li>• Any expiry date in the future, any CVV</li>
									</ul>
								</div>
							</div>
						</CardContent>
					</Card>
				{/if}

				<!-- Error Message -->
				{#if checkoutError}
					<div
						class="rounded-lg border border-red-200 bg-red-50 p-4 dark:border-red-800 dark:bg-red-950/30"
					>
						<p class="text-sm text-red-600 dark:text-red-400">
							{checkoutError}
						</p>
					</div>
				{/if}

				<!-- Action Buttons -->
				<div class="flex justify-end gap-3">
					<ButtonComponent variant="outline" onclick={handleClose} disabled={checkoutLoading}
						>Cancel</ButtonComponent
					>
					<ButtonComponent
						onclick={handleCheckout}
						disabled={checkoutLoading}
						class="min-w-[150px]"
					>
						{#if checkoutLoading}
							<div
								class="mr-2 inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
							></div>
							Processing...
						{:else}
							Continue to Checkout
						{/if}
					</ButtonComponent>
				</div>
			</div>
		</DialogContent>
	</Dialog>
{/if}

<style>
	/* Ensure Paddle overlay has highest z-index and is clickable */
	:global(.paddle-checkout-container) {
		z-index: 9999 !important;
		pointer-events: auto !important;
	}

	:global(.paddle-overlay) {
		z-index: 9999 !important;
		pointer-events: auto !important;
	}

	:global([data-paddle-overlay]) {
		z-index: 9999 !important;
		pointer-events: auto !important;
	}

	/* Ensure Paddle iframe is interactive */
	:global(.paddle-checkout-container iframe) {
		pointer-events: auto !important;
		z-index: 10000 !important;
	}
</style>
