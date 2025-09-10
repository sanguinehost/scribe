<script lang="ts">
	import { onMount } from 'svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { PaddleLoader, CheckoutButton, type PaymentPlan } from '$lib/components/payment';

	// Payment plans configuration
	const plans: PaymentPlan[] = [
		{
			id: 'free',
			name: 'Free',
			price: 0,
			currency: 'USD',
			interval: 'monthly',
			features: [
				'50,000 tokens per month',
				'Up to 5 characters',
				'1 lorebook',
				'Basic chat features',
				'Community support'
			]
		},
		{
			id: 'pro',
			name: 'Pro',
			price: 9.99,
			currency: 'USD',
			interval: 'monthly',
			popular: true,
			features: [
				'500,000 tokens per month',
				'Up to 50 characters',
				'10 lorebooks',
				'Advanced chat features',
				'Custom personas',
				'Priority support',
				'Advanced AI models'
			]
		},
		{
			id: 'enterprise',
			name: 'Enterprise',
			price: 29.99,
			currency: 'USD',
			interval: 'monthly',
			features: [
				'Unlimited tokens',
				'Unlimited characters',
				'Unlimited lorebooks',
				'All Pro features',
				'API access',
				'White-label options',
				'Dedicated support',
				'Custom integrations'
			]
		}
	];

	function handleCheckoutStart(event: CustomEvent<{ planType: string }>) {
		console.log('Checkout started for plan:', event.detail.planType);
	}

	function handleCheckoutSuccess(event: CustomEvent<{ checkoutUrl: string }>) {
		console.log('Checkout URL received:', event.detail.checkoutUrl);
	}

	function handleCheckoutError(event: CustomEvent<{ error: string }>) {
		console.error('Checkout error:', event.detail.error);
		// Could show a toast notification here
	}
</script>

<svelte:head>
	<title>Pricing - Sanguine Scribe</title>
	<meta name="description" content="Choose the perfect plan for your character AI conversations" />
</svelte:head>

{#if ENABLE_PAYMENTS}
	<!-- Load Paddle.js SDK -->
	<PaddleLoader />
{/if}

<div class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
	<div class="container mx-auto px-4 py-12">
		<!-- Header -->
		<div class="text-center mb-12">
			<h1 class="text-4xl font-bold text-slate-900 dark:text-slate-100 mb-4">
				Choose Your Plan
			</h1>
			<p class="text-xl text-slate-600 dark:text-slate-300 max-w-2xl mx-auto">
				Start your character AI journey with our free tier, or unlock advanced features with Pro and Enterprise plans.
			</p>
		</div>

		<!-- Pricing Cards -->
		<div class="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
			{#each plans as plan}
				<div class="relative bg-white dark:bg-slate-800 rounded-2xl shadow-lg border border-slate-200 dark:border-slate-700 p-8 {plan.popular ? 'ring-2 ring-blue-500 scale-105' : ''}">
					{#if plan.popular}
						<div class="absolute -top-4 left-1/2 transform -translate-x-1/2">
							<span class="bg-blue-500 text-white px-4 py-2 rounded-full text-sm font-medium">
								Most Popular
							</span>
						</div>
					{/if}

					<!-- Plan Header -->
					<div class="text-center mb-8">
						<h3 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-2">
							{plan.name}
						</h3>
						<div class="mb-4">
							{#if plan.price === 0}
								<span class="text-4xl font-bold text-slate-900 dark:text-slate-100">Free</span>
							{:else}
								<span class="text-4xl font-bold text-slate-900 dark:text-slate-100">
									${plan.price}
								</span>
								<span class="text-slate-600 dark:text-slate-300">/{plan.interval}</span>
							{/if}
						</div>
					</div>

					<!-- Features -->
					<ul class="space-y-4 mb-8">
						{#each plan.features as feature}
							<li class="flex items-start">
								<svg class="w-5 h-5 text-green-500 mt-0.5 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
									<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
								</svg>
								<span class="text-slate-600 dark:text-slate-300">{feature}</span>
							</li>
						{/each}
					</ul>

					<!-- CTA Button -->
					<div class="text-center">
						{#if plan.id === 'free'}
							<a
								href="/auth/signup"
								class="w-full inline-block bg-slate-600 hover:bg-slate-700 text-white font-medium py-3 px-6 rounded-lg transition-colors text-center"
							>
								Get Started Free
							</a>
						{:else if plan.id === 'enterprise'}
							<a
								href="mailto:support@sanguinehost.com?subject=Enterprise Plan Inquiry"
								class="w-full inline-block bg-slate-600 hover:bg-slate-700 text-white font-medium py-3 px-6 rounded-lg transition-colors text-center"
							>
								Contact Sales
							</a>
						{:else if ENABLE_PAYMENTS}
							<CheckoutButton
								planType={plan.id}
								buttonText="Subscribe to {plan.name}"
								buttonClass="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-6 rounded-lg transition-colors"
								on:checkout-start={handleCheckoutStart}
								on:checkout-success={handleCheckoutSuccess}
								on:checkout-error={handleCheckoutError}
							/>
						{:else}
							<button
								disabled
								class="w-full bg-slate-400 text-white font-medium py-3 px-6 rounded-lg cursor-not-allowed"
							>
								Payments Not Available
							</button>
						{/if}
					</div>
				</div>
			{/each}
		</div>

		<!-- FAQ Section -->
		<div class="mt-20 max-w-4xl mx-auto">
			<h2 class="text-3xl font-bold text-slate-900 dark:text-slate-100 text-center mb-12">
				Frequently Asked Questions
			</h2>
			
			<div class="space-y-8">
				<div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-lg">
					<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">
						What are tokens?
					</h3>
					<p class="text-slate-600 dark:text-slate-300">
						Tokens are units of AI processing power. On average, 1 token ≈ 0.75 words. A typical conversation message uses 50-200 tokens depending on length and context.
					</p>
				</div>

				<div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-lg">
					<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">
						Can I change plans at any time?
					</h3>
					<p class="text-slate-600 dark:text-slate-300">
						Yes! You can upgrade or downgrade your plan at any time. Changes take effect at the next billing cycle, and we'll prorate any differences.
					</p>
				</div>

				<div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-lg">
					<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">
						Is there a free trial?
					</h3>
					<p class="text-slate-600 dark:text-slate-300">
						Our Free plan gives you a taste of Sanguine Scribe with 50,000 tokens per month. You can upgrade to Pro or Enterprise at any time to unlock more features.
					</p>
				</div>

				<div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-lg">
					<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-2">
						What payment methods do you accept?
					</h3>
					<p class="text-slate-600 dark:text-slate-300">
						We accept all major credit cards, PayPal, and other payment methods through our secure payment processor Paddle.
					</p>
				</div>
			</div>
		</div>
	</div>
</div>