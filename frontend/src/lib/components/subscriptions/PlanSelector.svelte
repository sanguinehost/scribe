<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import {
		Card,
		CardContent,
		CardDescription,
		CardFooter,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import { Badge as BadgeComponent } from '$lib/components/ui/badge';
	import { Check, Zap, Star, Crown } from 'lucide-svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import type { PlanFeatures, PlanType } from '$lib/types/payment';

	interface Props {
		plans: PlanFeatures[];
		currentPlan?: PlanType;
		billingCycle: 'monthly' | 'yearly';
		onPlanSelect?: (planType: PlanType, billingCycle: 'monthly' | 'yearly') => void;
		onBillingCycleChange?: (cycle: 'monthly' | 'yearly') => void;
		selectedPlan?: PlanType;
		isLoading?: boolean;
	}

	let {
		plans = [],
		currentPlan = 'free',
		billingCycle = 'monthly',
		onPlanSelect = () => {},
		onBillingCycleChange = () => {},
		selectedPlan = undefined,
		isLoading = false
	}: Props = $props();

	const dispatch = createEventDispatcher();

	function handlePlanSelect(planType: PlanType) {
		if (planType === 'free') {
			// Free plan doesn't need checkout
			dispatch('planSelected', { planType, billingCycle: 'monthly' });
			onPlanSelect(planType, 'monthly');
		} else {
			dispatch('planSelected', { planType, billingCycle });
			onPlanSelect(planType, billingCycle);
		}
	}

	function handleBillingToggle() {
		const newCycle = billingCycle === 'monthly' ? 'yearly' : 'monthly';
		dispatch('billingCycleChanged', { billingCycle: newCycle });
		onBillingCycleChange(newCycle);
	}

	function getPlanIcon(planType: PlanType) {
		switch (planType) {
			case 'basic':
				return Zap;
			case 'premium':
				return Crown;
			default:
				return Star;
		}
	}

	function getDisplayPrice(plan: PlanFeatures): string {
		if (plan.plan_type === 'free') return 'Free';

		const features = plan.billing_features?.[billingCycle];
		if (features) {
			return features.display_price;
		}

		// Fallback to basic pricing
		return billingCycle === 'monthly'
			? `$${plan.price_monthly}/month`
			: `$${plan.price_yearly}/year`;
	}

	function getSavingsMessage(plan: PlanFeatures): string | null {
		if (billingCycle !== 'yearly' || plan.plan_type === 'free') return null;

		const features = plan.billing_features?.yearly;
		if (features?.savings_message) {
			return features.savings_message;
		}

		// Calculate savings if not provided
		if (plan.annual_savings_percent) {
			const annualSavings = (plan.price_monthly * 12 * plan.annual_savings_percent) / 100;
			return `Save $${annualSavings.toFixed(0)} per year`;
		}

		return null;
	}

	function getMonthlyEquivalent(plan: PlanFeatures): string | null {
		if (billingCycle !== 'yearly' || plan.plan_type === 'free') return null;

		const features = plan.billing_features?.yearly;
		if (features?.monthly_equivalent) {
			return features.monthly_equivalent;
		}

		// Calculate equivalent if not provided
		if (plan.price_yearly) {
			const monthlyEquiv = plan.price_yearly / 12;
			return `$${monthlyEquiv.toFixed(2)}/month`;
		}

		return null;
	}

	function isCurrentPlan(planType: PlanType): boolean {
		return currentPlan === planType;
	}

	function isRecommended(planType: PlanType): boolean {
		return planType === 'basic'; // Basic is recommended for most users
	}

	function getFeatureList(plan: PlanFeatures): string[] {
		const features = [];

		// Message limits
		if (plan.limits.daily_messages === -1) {
			features.push('Unlimited messages');
		} else {
			features.push(`${plan.limits.daily_messages} messages/day`);
		}

		// Context tokens
		const contextK = plan.limits.context_tokens / 1000;
		features.push(`${contextK}K context window`);

		// Credits
		if (plan.credits.included_monthly > 0) {
			features.push(`${plan.credits.included_monthly} credits/month`);
		}

		// Advanced features
		if (plan.limits.chronicles_enabled) features.push('Chronicle system');
		if (plan.limits.lorebooks_enabled) features.push('Lorebooks');
		if (plan.limits.personas_enabled) features.push('Custom personas');
		if (plan.features.api_access) features.push('API access');
		if (plan.features.priority_support) features.push('Priority support');
		if (plan.features.beta_features) features.push('Beta features');

		return features.slice(0, 6); // Limit to 6 features for clean display
	}
</script>

{#if ENABLE_PAYMENTS}
	<div class="mx-auto w-full max-w-6xl space-y-8">
		<!-- Billing Cycle Toggle -->
		<div class="flex justify-center">
			<div class="flex items-center rounded-lg bg-muted p-1">
				<button
					class="rounded-md px-4 py-2 text-sm font-medium transition-all duration-200 {billingCycle ===
					'monthly'
						? 'bg-background text-foreground shadow-sm'
						: 'text-muted-foreground hover:text-foreground'}"
					onclick={() => billingCycle === 'yearly' && handleBillingToggle()}
					disabled={isLoading}
				>
					Monthly
				</button>
				<button
					class="relative rounded-md px-4 py-2 text-sm font-medium transition-all duration-200 {billingCycle ===
					'yearly'
						? 'bg-background text-foreground shadow-sm'
						: 'text-muted-foreground hover:text-foreground'}"
					onclick={() => billingCycle === 'monthly' && handleBillingToggle()}
					disabled={isLoading}
				>
					Yearly
					<BadgeComponent
						variant="secondary"
						class="absolute -right-2 -top-2 px-1.5 py-0.5 text-xs"
					>
						Save 17%
					</BadgeComponent>
				</button>
			</div>
		</div>

		<!-- Plan Cards -->
		<div class="grid grid-cols-1 gap-6 md:grid-cols-3">
			{#each plans as plan (plan.plan_type)}
				{@const Icon = getPlanIcon(plan.plan_type)}
				{@const price = getDisplayPrice(plan)}
				{@const savings = getSavingsMessage(plan)}
				{@const monthlyEquiv = getMonthlyEquivalent(plan)}
				{@const features = getFeatureList(plan)}
				{@const isCurrent = isCurrentPlan(plan.plan_type)}
				{@const recommended = isRecommended(plan.plan_type)}

				<div class="relative">
					{#if recommended && billingCycle === 'yearly'}
						<div class="absolute -top-3 left-1/2 z-10 -translate-x-1/2 transform">
							<BadgeComponent class="bg-primary text-primary-foreground"
								>Most Popular</BadgeComponent
							>
						</div>
					{/if}

					<Card
						class="relative h-full {recommended && billingCycle === 'yearly'
							? 'scale-105 border-primary shadow-lg'
							: ''} {selectedPlan === plan.plan_type
							? 'ring-2 ring-primary ring-offset-2'
							: ''} transition-all duration-200 hover:shadow-md"
					>
						<CardHeader class="space-y-4 text-center">
							<div class="flex justify-center">
								<div class="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
									<Icon class="h-6 w-6 text-primary" />
								</div>
							</div>

							<div>
								<CardTitle class="text-xl">{plan.display_name}</CardTitle>
								<CardDescription class="mt-2">{plan.description}</CardDescription>
							</div>

							<div class="space-y-1">
								<div class="text-3xl font-bold">
									{price}
								</div>
								{#if monthlyEquiv}
									<div class="text-sm text-muted-foreground">
										{monthlyEquiv}
									</div>
								{/if}
								{#if savings}
									<div class="text-sm font-medium text-green-600 dark:text-green-400">
										{savings}
									</div>
								{/if}
							</div>
						</CardHeader>

						<CardContent class="space-y-4">
							<ul class="space-y-3">
								{#each features as feature}
									<li class="flex items-center gap-3">
										<Check class="h-4 w-4 flex-shrink-0 text-green-500" />
										<span class="text-sm">{feature}</span>
									</li>
								{/each}
							</ul>
						</CardContent>

						<CardFooter>
							{#if isCurrent}
								<ButtonComponent disabled class="w-full" variant="outline"
									>Current Plan</ButtonComponent
								>
							{:else}
								<ButtonComponent
									class="w-full {recommended && billingCycle === 'yearly'
										? 'bg-primary hover:bg-primary/90'
										: ''}"
									variant={recommended && billingCycle === 'yearly' ? 'default' : 'outline'}
									disabled={isLoading}
									onclick={() => handlePlanSelect(plan.plan_type)}
								>
									{#if plan.plan_type === 'free'}
										Start Free
									{:else if currentPlan === 'free'}
										Upgrade to {plan.display_name}
									{:else}
										Switch to {plan.display_name}
									{/if}
								</ButtonComponent>
							{/if}
						</CardFooter>
					</Card>
				</div>
			{/each}
		</div>

		<!-- Additional Information -->
		<div class="space-y-2 text-center text-sm text-muted-foreground">
			<p>All plans include unlimited character conversations and export functionality.</p>
			<p>Cancel anytime. No long-term contracts.</p>
		</div>
	</div>
{/if}
