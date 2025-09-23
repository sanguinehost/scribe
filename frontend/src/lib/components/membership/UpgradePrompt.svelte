<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button } from '$lib/components/ui/button';
	import { CheckoutButton } from '$lib/components/payment';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { AlertTriangle, Zap } from 'lucide-svelte';

	export let variant: 'banner' | 'modal' | 'inline' = 'inline';
	export let showCloseButton: boolean = true;
	export let title: string = 'Token Limit Reached';
	export let message: string = 'You have reached your token limit. Please upgrade your plan to continue chatting.';

	const dispatch = createEventDispatcher<{
		close: void;
		upgrade: { planType: string };
	}>();

	function handleClose() {
		dispatch('close');
	}

	function handleUpgrade(planType: string) {
		dispatch('upgrade', { planType });
	}

	// No longer using token percentage since we moved away from token limits
	$: usagePercent = 0;
</script>

<div class="upgrade-prompt upgrade-prompt-{variant}" class:banner-gradient={variant === 'banner'}>
	{#if variant === 'banner'}
		<div class="flex items-center gap-3 p-4 border border-red-200 dark:border-red-800 rounded-lg">
			<div class="flex-shrink-0">
				<AlertTriangle class="h-5 w-5 text-red-600 dark:text-red-400" />
			</div>
			<div class="flex-1 min-w-0">
				<h3 class="text-sm font-medium text-red-800 dark:text-red-200">{title}</h3>
				<p class="text-sm text-red-700 dark:text-red-300 mt-1">{message}</p>
				{#if subscriptionStore.usageLimits && !subscriptionStore.usageLimits.is_unlimited}
					<div class="text-xs text-red-600 dark:text-red-400 mt-1">
						{subscriptionStore.usageLimits.tokens_used_total.toLocaleString()} tokens used this period
					</div>
				{/if}
			</div>
			<div class="flex-shrink-0 flex gap-2">
				<CheckoutButton
					planType="premium"
					buttonText="Upgrade Now"
					buttonClass="bg-red-600 hover:bg-red-700 text-white px-3 py-1 text-sm rounded border-none cursor-pointer"
					urgent={subscriptionStore.isAtLimit}
					on:checkout-start={() => handleUpgrade('premium')}
				/>
				{#if showCloseButton}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleClose}
						class="text-red-600 hover:text-red-700 hover:bg-red-100 dark:text-red-400 dark:hover:text-red-300 dark:hover:bg-red-950/50"
					>
						✕
					</Button>
				{/if}
			</div>
		</div>
	{:else if variant === 'modal'}
		<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
			<div class="bg-white dark:bg-slate-900 rounded-lg p-6 max-w-md mx-4 shadow-xl">
				<div class="flex items-center gap-3 mb-4">
					<div class="flex-shrink-0">
						<AlertTriangle class="h-6 w-6 text-red-600 dark:text-red-400" />
					</div>
					<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
				</div>
				
				<p class="text-slate-700 dark:text-slate-300 mb-4">{message}</p>
				
				{#if subscriptionStore.usageLimits && !subscriptionStore.usageLimits.is_unlimited}
					<div class="bg-slate-100 dark:bg-slate-800 rounded p-3 mb-4">
						<div class="text-sm text-slate-600 dark:text-slate-400 mb-2">Current Usage</div>
						<div class="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2">
							<div class="bg-red-600 h-2 rounded-full" style="width: {usagePercent}%"></div>
						</div>
						<div class="text-xs text-slate-500 dark:text-slate-400 mt-1">
							{subscriptionStore.usageLimits.tokens_used_total.toLocaleString()} tokens used this period
						</div>
					</div>
				{/if}

				<div class="flex flex-col gap-3">
					<CheckoutButton
						planType="premium"
						buttonText="Upgrade to Premium Plan"
						buttonClass="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded cursor-pointer border-none"
						urgent={subscriptionStore.isAtLimit}
						on:checkout-start={() => handleUpgrade('premium')}
					/>
					{#if showCloseButton}
						<Button variant="ghost" onclick={handleClose} class="w-full">
							Cancel
						</Button>
					{/if}
				</div>
			</div>
		</div>
	{:else}
		<!-- Inline variant -->
		<div class="flex items-center gap-3 p-3 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 rounded">
			<AlertTriangle class="h-4 w-4 text-red-600 dark:text-red-400 flex-shrink-0" />
			<div class="flex-1 min-w-0">
				<span class="text-sm text-red-700 dark:text-red-300">{message}</span>
			</div>
			<CheckoutButton
				planType="premium"
				buttonText="Upgrade"
				buttonClass="bg-red-600 hover:bg-red-700 text-white px-2 py-1 text-xs rounded cursor-pointer border-none"
				urgent={subscriptionStore.isAtLimit}
				on:checkout-start={() => handleUpgrade('premium')}
			/>
			{#if showCloseButton}
				<Button
					variant="ghost"
					size="sm"
					onclick={handleClose}
					class="text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 p-1"
				>
					✕
				</Button>
			{/if}
		</div>
	{/if}
</div>

<style>
	.upgrade-prompt {
		animation: slideIn 0.3s ease-out;
	}

	.upgrade-prompt-banner {
		animation: slideIn 0.3s ease-out, pulse 2s infinite;
	}

	@keyframes slideIn {
		from {
			opacity: 0;
			transform: translateY(-10px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	@keyframes pulse {
		0%, 100% {
			box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4);
		}
		50% {
			box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.1);
		}
	}

	.upgrade-prompt-banner:hover {
		animation: slideIn 0.3s ease-out;
	}

	.banner-gradient {
		background: linear-gradient(to right, #fef2f2, #fff7ed);
	}

	:global(.dark) .banner-gradient {
		background: linear-gradient(to right, rgba(69, 26, 3, 0.2), rgba(124, 45, 18, 0.2));
	}
</style>