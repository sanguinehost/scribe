<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { CheckoutButton } from '$lib/components/payment';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { AlertTriangle, Zap as _Zap } from 'lucide-svelte';

	let {
		variant = 'inline',
		showCloseButton = true,
		title = 'Token Limit Reached',
		message = 'You have reached your token limit. Please upgrade your plan to continue chatting.'
	}: {
		variant?: 'banner' | 'modal' | 'inline';
		showCloseButton?: boolean;
		title?: string;
		message?: string;
	} = $props();

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
	let usagePercent = 0;
</script>

<div class="upgrade-prompt upgrade-prompt-{variant}" class:banner-gradient={variant === 'banner'}>
	{#if variant === 'banner'}
		<div class="flex items-center gap-3 rounded-lg border border-red-200 p-4 dark:border-red-800">
			<div class="flex-shrink-0">
				<AlertTriangle class="h-5 w-5 text-red-600 dark:text-red-400" />
			</div>
			<div class="min-w-0 flex-1">
				<h3 class="text-sm font-medium text-red-800 dark:text-red-200">{title}</h3>
				<p class="mt-1 text-sm text-red-700 dark:text-red-300">{message}</p>
				{#if subscriptionStore.usageLimits && !subscriptionStore.usageLimits.is_unlimited}
					<div class="mt-1 text-xs text-red-600 dark:text-red-400">
						{subscriptionStore.usageLimits.tokens_used_total.toLocaleString()} tokens used this period
					</div>
				{/if}
			</div>
			<div class="flex flex-shrink-0 gap-2">
				<CheckoutButton
					planType="premium"
					buttonText="Upgrade Now"
					buttonClass="bg-red-600 hover:bg-red-700 text-white px-3 py-1 text-sm rounded border-none cursor-pointer"
					urgent={subscriptionStore.isAtLimit}
					on:checkout-start={() => handleUpgrade('premium')}
				/>
				{#if showCloseButton}
					<ButtonComponent
						variant="ghost"
						size="sm"
						onclick={handleClose}
						class="text-red-600 hover:bg-red-100 hover:text-red-700 dark:text-red-400 dark:hover:bg-red-950/50 dark:hover:text-red-300"
					>
						✕
					</ButtonComponent>
				{/if}
			</div>
		</div>
	{:else if variant === 'modal'}
		<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
			<div class="mx-4 max-w-md rounded-lg bg-white p-6 shadow-xl dark:bg-slate-900">
				<div class="mb-4 flex items-center gap-3">
					<div class="flex-shrink-0">
						<AlertTriangle class="h-6 w-6 text-red-600 dark:text-red-400" />
					</div>
					<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
				</div>

				<p class="mb-4 text-slate-700 dark:text-slate-300">{message}</p>

				{#if subscriptionStore.usageLimits && !subscriptionStore.usageLimits.is_unlimited}
					<div class="mb-4 rounded bg-slate-100 p-3 dark:bg-slate-800">
						<div class="mb-2 text-sm text-slate-600 dark:text-slate-400">Current Usage</div>
						<div class="h-2 w-full rounded-full bg-slate-200 dark:bg-slate-700">
							<div class="h-2 rounded-full bg-red-600" style="width: {usagePercent}%"></div>
						</div>
						<div class="mt-1 text-xs text-slate-500 dark:text-slate-400">
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
						<ButtonComponent variant="ghost" onclick={handleClose} class="w-full"
							>Cancel</ButtonComponent
						>
					{/if}
				</div>
			</div>
		</div>
	{:else}
		<!-- Inline variant -->
		<div
			class="flex items-center gap-3 rounded border border-red-200 bg-red-50 p-3 dark:border-red-800 dark:bg-red-950/20"
		>
			<AlertTriangle class="h-4 w-4 flex-shrink-0 text-red-600 dark:text-red-400" />
			<div class="min-w-0 flex-1">
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
				<ButtonComponent
					variant="ghost"
					size="sm"
					onclick={handleClose}
					class="p-1 text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
				>
					✕
				</ButtonComponent>
			{/if}
		</div>
	{/if}
</div>

<style>
	.upgrade-prompt {
		animation: slideIn 0.3s ease-out;
	}

	.upgrade-prompt-banner {
		animation:
			slideIn 0.3s ease-out,
			pulse 2s infinite;
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
		0%,
		100% {
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
