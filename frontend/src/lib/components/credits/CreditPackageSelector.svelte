<script lang="ts">
	import { onMount } from 'svelte';
	import { creditStore } from '$lib/stores/credits';
	import { PAYMENT_FEATURES } from '$lib/utils/features';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Badge as BadgeComponent } from '$lib/components/ui/badge';
	import { Coins, Zap, Star, Loader } from 'lucide-svelte';
	import type { CreditPackage } from '$lib/types/payment';

	export let onPackageSelect: (pkg: CreditPackage) => void = () => {};
	export let selectedPackageId: string | null = null;

	let packages: CreditPackage[] = [];
	let isLoading = false;
	let error: string | null = null;

	// Subscribe to credit store
	$: {
		packages = $creditStore.packages;
		isLoading = $creditStore.isLoading;
		error = $creditStore.error;
	}

	onMount(async () => {
		if (!PAYMENT_FEATURES.credits) {
			return;
		}

		try {
			await creditStore.fetchPackages();
		} catch (err) {
			console.error('Failed to fetch credit packages:', err);
		}
	});

	function formatPrice(priceCents: number, currency: string): string {
		const price = priceCents / 100;
		return new Intl.NumberFormat('en-US', {
			style: 'currency',
			currency: currency.toUpperCase()
		}).format(price);
	}

	function formatCredits(credits: number): string {
		return credits.toLocaleString();
	}

	function getBestValuePackage(): string | null {
		if (packages.length === 0) return null;

		// Find package with highest bonus percentage
		const bestValue = packages.reduce((best, pkg) => {
			const bonus = pkg.bonus_percentage || 0;
			const bestBonus = best.bonus_percentage || 0;
			return bonus > bestBonus ? pkg : best;
		}, packages[0]);

		return bestValue.package_id;
	}

	function getPopularPackage(): string | null {
		if (packages.length === 0) return null;

		// Find middle-tier package or one with good value
		const sorted = [...packages].sort((a, b) => a.price_cents - b.price_cents);
		const middleIndex = Math.floor(sorted.length / 2);
		return sorted[middleIndex]?.package_id || null;
	}

	$: bestValueId = getBestValuePackage();
	$: popularId = getPopularPackage();
</script>

{#if !PAYMENT_FEATURES.credits}
	<div class="py-8 text-center text-muted-foreground">
		<Coins class="mx-auto mb-3 h-12 w-12 opacity-50" />
		<p class="text-sm">Credit system is not available</p>
	</div>
{:else}
	<div class="space-y-4">
		<div class="text-center">
			<h3 class="mb-2 text-lg font-semibold">Choose Your Credit Package</h3>
			<p class="text-sm text-muted-foreground">Select a package to add credits to your account</p>
		</div>

		{#if error}
			<div class="py-8 text-center">
				<div class="mb-4 text-sm text-destructive">
					Failed to load credit packages: {error}
				</div>
				<ButtonComponent variant="outline" size="sm" onclick={() => creditStore.fetchPackages()}>
					Retry
				</ButtonComponent>
			</div>
		{:else if isLoading}
			<div class="flex items-center justify-center py-8">
				<Loader class="mr-2 h-6 w-6 animate-spin" />
				<span class="text-sm text-muted-foreground">Loading packages...</span>
			</div>
		{:else if packages.length === 0}
			<div class="py-8 text-center text-muted-foreground">
				<Coins class="mx-auto mb-3 h-12 w-12 opacity-50" />
				<p class="text-sm">No credit packages available</p>
			</div>
		{:else}
			<div class="grid gap-3 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
				{#each packages
					.filter((pkg) => pkg.active)
					.sort((a, b) => a.display_order - b.display_order) as pkg (pkg.package_id)}
					<Card.Root
						class="relative cursor-pointer transition-all hover:shadow-md {selectedPackageId ===
						pkg.package_id
							? 'ring-2 ring-primary'
							: ''}"
						onclick={() => onPackageSelect(pkg)}
					>
						{#if pkg.package_id === bestValueId}
							<div class="absolute -right-2 -top-2">
								<BadgeComponent
									variant="secondary"
									class="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
								>
									<Star class="mr-1 h-3 w-3" />
									Best Value
								</BadgeComponent>
							</div>
						{:else if pkg.package_id === popularId}
							<div class="absolute -right-2 -top-2">
								<BadgeComponent
									variant="secondary"
									class="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
								>
									<Zap class="mr-1 h-3 w-3" />
									Popular
								</BadgeComponent>
							</div>
						{/if}

						<Card.Header class="pb-3">
							<Card.Title class="text-base">{pkg.name}</Card.Title>
							<div class="text-2xl font-bold">
								{formatPrice(pkg.price_cents, pkg.currency)}
							</div>
						</Card.Header>

						<Card.Content class="space-y-3">
							<div class="flex items-center gap-2">
								<Coins class="h-4 w-4 text-primary" />
								<span class="font-medium">{formatCredits(pkg.credits)} credits</span>
							</div>

							{#if pkg.bonus_percentage && pkg.bonus_percentage > 0}
								<div class="text-sm font-medium text-green-600 dark:text-green-400">
									+{pkg.bonus_percentage}% bonus credits
								</div>
							{/if}

							<div class="text-xs text-muted-foreground">
								≈ ${((pkg.price_cents / pkg.credits) * 100).toFixed(3)} per credit
							</div>

							<ButtonComponent
								variant={selectedPackageId === pkg.package_id ? 'default' : 'outline'}
								size="sm"
								class="w-full"
								onclick={(e) => {
									e.stopPropagation();
									onPackageSelect(pkg);
								}}
							>
								{selectedPackageId === pkg.package_id ? 'Selected' : 'Select Package'}
							</ButtonComponent>
						</Card.Content>
					</Card.Root>
				{/each}
			</div>

			{#if packages.length > 0}
				<div class="pt-4 text-center">
					<p class="text-xs text-muted-foreground">
						Credits never expire and can be used for any AI model
					</p>
				</div>
			{/if}
		{/if}
	</div>
{/if}
