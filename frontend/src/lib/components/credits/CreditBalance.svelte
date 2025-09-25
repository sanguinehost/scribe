<script lang="ts">
	import { onMount } from 'svelte';
	import {
		creditStore,
		formattedBalance,
		usagePercentage,
		isNearLimit,
		isOverLimit
	} from '$lib/stores/credits';
	import { PAYMENT_FEATURES } from '$lib/utils/features';
	import { Coins, AlertCircle, TrendingUp, Clock } from 'lucide-svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Progress from '$lib/components/ui/progress';
	import * as Tooltip from '$lib/components/ui/tooltip';

	export let compact = false;
	export let showPurchaseButton = true;
	export let onPurchaseClick = () => {};

	// Fetch balance and model costs on mount
	onMount(async () => {
		if (!PAYMENT_FEATURES.credits) {
			return;
		}

		try {
			await Promise.all([creditStore.fetchBalance(), creditStore.fetchModelCosts()]);
		} catch (error) {
			console.error('Failed to fetch credit data:', error);
		}
	});

	// Auto-refresh balance every 5 minutes
	const refreshInterval = setInterval(
		() => {
			if (PAYMENT_FEATURES.credits) {
				creditStore.fetchBalance();
			}
		},
		5 * 60 * 1000
	);

	// Cleanup
	onMount(() => {
		return () => clearInterval(refreshInterval);
	});

	$: balance = $creditStore.balance;
	$: dailyUsage = $creditStore.dailyUsage;
	$: isLoading = $creditStore.isLoading;
	$: error = $creditStore.error;
</script>

{#if !PAYMENT_FEATURES.credits}
	<!-- Credits feature disabled -->
{:else if compact}
	<!-- Compact view for header/sidebar -->
	<div class="flex items-center gap-2">
		<Tooltip.Root>
			<Tooltip.Trigger
				class="flex items-center gap-1.5 rounded-md px-2 py-1 transition-colors hover:bg-accent {$isNearLimit &&
				!$isOverLimit
					? 'text-orange-500'
					: ''} {$isOverLimit ? 'text-red-500' : ''}"
			>
				<Coins class="h-4 w-4" />
				<span class="font-medium">{$formattedBalance}</span>
				{#if $isNearLimit || $isOverLimit}
					<AlertCircle class="h-3.5 w-3.5" />
				{/if}
			</Tooltip.Trigger>
			<Tooltip.Content>
				<div class="space-y-1">
					<p class="font-medium">Credit Balance: {$formattedBalance}</p>
					{#if dailyUsage}
						<p class="text-sm text-muted-foreground">
							Daily Usage: {dailyUsage.message_count} / {dailyUsage.daily_limit}
						</p>
					{/if}
					{#if balance?.last_monthly_grant}
						<p class="text-sm text-muted-foreground">
							Last Grant: {new Date(balance.last_monthly_grant).toLocaleDateString()}
						</p>
					{/if}
				</div>
			</Tooltip.Content>
		</Tooltip.Root>

		{#if showPurchaseButton}
			<Button variant="outline" size="sm" on:click={onPurchaseClick}>
				<TrendingUp class="mr-1 h-3.5 w-3.5" />
				Buy
			</Button>
		{/if}
	</div>
{:else}
	<!-- Full card view -->
	<Card.Root class="w-full">
		<Card.Header>
			<div class="flex items-center justify-between">
				<Card.Title class="flex items-center gap-2">
					<Coins class="h-5 w-5" />
					Credit Balance
				</Card.Title>
				{#if showPurchaseButton}
					<Button variant="outline" size="sm" on:click={onPurchaseClick}>
						<TrendingUp class="mr-1.5 h-4 w-4" />
						Purchase Credits
					</Button>
				{/if}
			</div>
			<Card.Description>Manage your credits and track usage</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			{#if error}
				<div class="flex items-center gap-2 text-destructive">
					<AlertCircle class="h-4 w-4" />
					<span class="text-sm">{error}</span>
				</div>
			{:else if isLoading && !balance}
				<div class="animate-pulse space-y-3">
					<div class="h-8 w-32 rounded bg-muted"></div>
					<div class="h-2 w-full rounded bg-muted"></div>
					<div class="h-4 w-48 rounded bg-muted"></div>
				</div>
			{:else if balance}
				<!-- Current Balance -->
				<div>
					<div class="mb-1 flex items-baseline gap-2">
						<span class="text-3xl font-bold">{balance.balance.toLocaleString()}</span>
						<span class="text-muted-foreground">credits</span>
					</div>
					{#if balance.updated_at}
						<p class="text-xs text-muted-foreground">
							Last updated: {new Date(balance.updated_at).toLocaleString()}
						</p>
					{/if}
				</div>

				<!-- Daily Usage Progress -->
				{#if dailyUsage}
					<div class="space-y-2">
						<div class="flex items-center justify-between text-sm">
							<span class="text-muted-foreground">Daily Usage</span>
							<span
								class="font-medium {$isNearLimit && !$isOverLimit
									? 'text-orange-500'
									: ''} {$isOverLimit ? 'text-red-500' : ''}"
							>
								{dailyUsage.message_count} / {dailyUsage.daily_limit} messages
							</span>
						</div>
						<Progress.Root value={$usagePercentage} class="h-2" />
						{#if dailyUsage.reset_time}
							<p class="flex items-center gap-1 text-xs text-muted-foreground">
								<Clock class="h-3 w-3" />
								Resets at {dailyUsage.reset_time}
							</p>
						{/if}
					</div>
				{/if}

				<!-- Lifetime Stats -->
				<div class="grid grid-cols-2 gap-4 pt-2">
					<div>
						<p class="text-sm text-muted-foreground">Lifetime Earned</p>
						<p class="text-lg font-medium text-green-600 dark:text-green-400">
							+{balance.lifetime_earned.toLocaleString()}
						</p>
					</div>
					<div>
						<p class="text-sm text-muted-foreground">Lifetime Spent</p>
						<p class="text-lg font-medium text-red-600 dark:text-red-400">
							-{balance.lifetime_spent.toLocaleString()}
						</p>
					</div>
				</div>

				<!-- Monthly Grant Info -->
				{#if balance.last_monthly_grant}
					<div class="border-t pt-2">
						<p class="text-sm text-muted-foreground">
							Last monthly grant received on {new Date(
								balance.last_monthly_grant
							).toLocaleDateString()}
						</p>
					</div>
				{/if}
			{:else}
				<div class="py-4 text-center text-muted-foreground">No credit data available</div>
			{/if}
		</Card.Content>
	</Card.Root>
{/if}
