<script lang="ts">
	import {
		Card,
		CardContent,
		CardDescription,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import { Separator } from '$lib/components/ui/separator';
	import { Badge as BadgeComponent } from '$lib/components/ui/badge';
	import { Calendar, CreditCard, Shield, RotateCcw } from 'lucide-svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import type { OrderPreview, PlanFeatures } from '$lib/types/payment';

	interface Props {
		orderPreview?: OrderPreview | null;
		planFeatures?: PlanFeatures | null;
		isLoading?: boolean;
		showCancellationPolicy?: boolean;
	}

	let {
		orderPreview = null,
		planFeatures = null,
		isLoading = false,
		showCancellationPolicy = true
	}: Props = $props();

	function formatCurrency(amount: number, currency: string = 'USD'): string {
		return new Intl.NumberFormat('en-US', {
			style: 'currency',
			currency: currency
		}).format(amount);
	}

	function formatDate(dateString: string): string {
		return new Date(dateString).toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'long',
			day: 'numeric'
		});
	}

	function getBillingCycleText(period: 'monthly' | 'yearly'): string {
		return period === 'monthly' ? 'Monthly billing' : 'Annual billing';
	}

	function getNextBillingText(period: 'monthly' | 'yearly'): string {
		return period === 'monthly' ? 'Next month' : 'Next year';
	}

	// Fallback data if no orderPreview is provided but planFeatures is available
	const fallbackOrder = $derived(() => {
		if (orderPreview || !planFeatures) return null;

		const isYearly = planFeatures.billing_features?.yearly && planFeatures.price_yearly;
		const amount = isYearly ? planFeatures.price_yearly! : planFeatures.price_monthly;
		const period = isYearly ? 'yearly' : 'monthly';

		return {
			plan_name: planFeatures.display_name,
			plan_type: planFeatures.plan_type,
			billing_period: period,
			line_items: [
				{
					description: `${planFeatures.display_name} Plan`,
					billing_period: getBillingCycleText(period),
					amount,
					currency: 'USD'
				}
			],
			subtotal: amount,
			tax_amount: 0,
			total_amount: amount,
			currency: 'USD',
			next_billing_date: new Date(
				Date.now() + (period === 'monthly' ? 30 : 365) * 24 * 60 * 60 * 1000
			).toISOString(),
			savings_message: isYearly
				? planFeatures.billing_features?.yearly?.savings_message
				: undefined,
			cancellation_policy: 'Cancel anytime. No cancellation fees.'
		} as OrderPreview;
	});

	const displayOrder = $derived(orderPreview || fallbackOrder());
</script>

{#if ENABLE_PAYMENTS && displayOrder}
	<Card class="w-full max-w-md">
		<CardHeader>
			<CardTitle class="flex items-center gap-2">
				<CreditCard class="h-5 w-5" />
				Order Summary
			</CardTitle>
			<CardDescription>Review your subscription details before checkout</CardDescription>
		</CardHeader>

		<CardContent class="space-y-6">
			{#if isLoading}
				<!-- Loading state -->
				<div class="space-y-4">
					<div class="h-4 animate-pulse rounded bg-muted"></div>
					<div class="h-4 w-3/4 animate-pulse rounded bg-muted"></div>
					<div class="h-4 w-1/2 animate-pulse rounded bg-muted"></div>
				</div>
			{:else}
				<!-- Plan Information -->
				<div class="space-y-3">
					<div class="flex items-center justify-between">
						<div>
							<h3 class="font-semibold">{displayOrder.plan_name} Plan</h3>
							<p class="text-sm text-muted-foreground">
								{getBillingCycleText(displayOrder.billing_period)}
							</p>
						</div>
						{#if displayOrder.billing_period === 'yearly'}
							<BadgeComponent variant="secondary" class="text-green-600"
								>Annual savings</BadgeComponent
							>
						{/if}
					</div>

					{#if displayOrder.savings_message}
						<div
							class="rounded-lg border border-green-200 bg-green-50 p-3 dark:border-green-800 dark:bg-green-950"
						>
							<p class="text-sm font-medium text-green-800 dark:text-green-200">
								💰 {displayOrder.savings_message}
							</p>
						</div>
					{/if}
				</div>

				<!-- Line Items -->
				<div class="space-y-3">
					{#each displayOrder.line_items as item, i (i)}
						<div class="flex items-center justify-between">
							<div class="flex-1">
								<p class="text-sm font-medium">{item.description}</p>
								<p class="text-xs text-muted-foreground">{item.billing_period}</p>
							</div>
							<span class="font-medium">
								{formatCurrency(item.amount, item.currency)}
							</span>
						</div>
					{/each}
				</div>

				<Separator />

				<!-- Pricing Breakdown -->
				<div class="space-y-2">
					<div class="flex items-center justify-between text-sm">
						<span>Subtotal</span>
						<span>{formatCurrency(displayOrder.subtotal, displayOrder.currency)}</span>
					</div>

					{#if displayOrder.tax_amount > 0}
						<div class="flex items-center justify-between text-sm">
							<span>Tax</span>
							<span>{formatCurrency(displayOrder.tax_amount, displayOrder.currency)}</span>
						</div>
					{/if}

					<Separator />

					<div class="flex items-center justify-between font-semibold">
						<span>Total</span>
						<span class="text-lg">
							{formatCurrency(displayOrder.total_amount, displayOrder.currency)}
						</span>
					</div>
				</div>

				<!-- Billing Information -->
				<div class="space-y-3 pt-2">
					<div class="flex items-center gap-3 text-sm">
						<Calendar class="h-4 w-4 text-muted-foreground" />
						<div>
							<p class="font-medium">Next billing date</p>
							<p class="text-muted-foreground">
								{formatDate(displayOrder.next_billing_date)}
							</p>
						</div>
					</div>

					<div class="flex items-center gap-3 text-sm">
						<RotateCcw class="h-4 w-4 text-muted-foreground" />
						<div>
							<p class="font-medium">Renewal</p>
							<p class="text-muted-foreground">
								Auto-renews {getNextBillingText(displayOrder.billing_period).toLowerCase()}
							</p>
						</div>
					</div>

					{#if showCancellationPolicy}
						<div class="flex items-center gap-3 text-sm">
							<Shield class="h-4 w-4 text-muted-foreground" />
							<div>
								<p class="font-medium">Cancellation</p>
								<p class="text-muted-foreground">
									{displayOrder.cancellation_policy}
								</p>
							</div>
						</div>
					{/if}
				</div>

				<!-- Security Notice -->
				<div class="rounded-lg bg-muted/50 p-3">
					<p class="text-center text-xs text-muted-foreground">
						🔒 Secure checkout powered by Paddle.<br />
						Your payment information is encrypted and protected.
					</p>
				</div>
			{/if}
		</CardContent>
	</Card>
{/if}
