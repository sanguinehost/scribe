<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import CheckoutOverlay from './CheckoutOverlay.svelte';
	import type { PlanType } from '$lib/types';

	// Props
	export let planType: PlanType = 'basic';
	export let disabled: boolean = false;
	export let loading: boolean = false;
	export let buttonText: string = 'Subscribe';
	export let buttonClass: string = 'btn-primary';
	export let urgent: boolean = false; // Add urgent styling for critical situations

	// State
	let isOverlayOpen = false;
	let checkoutLoading = false;
	let checkoutError: string | null = null;

	const dispatch = createEventDispatcher<{
		'checkout-start': { planType: PlanType };
		'checkout-complete': { transactionId: string };
		'checkout-error': { error: string };
	}>();

	/**
	 * Open checkout overlay
	 */
	function handleOpenCheckout() {
		if (!browser || !ENABLE_PAYMENTS || disabled || loading) {
			return;
		}

		isOverlayOpen = true;
		dispatch('checkout-start', { planType });
	}

	/**
	 * Handle checkout completion
	 */
	function handleCheckoutComplete(event: CustomEvent<{ transactionId: string }>) {
		dispatch('checkout-complete', event.detail);
		isOverlayOpen = false;
	}

	/**
	 * Handle overlay close
	 */
	function handleOverlayClose() {
		isOverlayOpen = false;
	}

	// Determine if button should be disabled
	$: isDisabled = disabled || loading || checkoutLoading || !ENABLE_PAYMENTS;
	$: displayText = checkoutLoading ? 'Processing...' : loading ? 'Loading...' : buttonText;
	$: showSpinner = checkoutLoading || loading;
</script>

{#if ENABLE_PAYMENTS}
	<button
		class="{buttonClass} {urgent ? 'urgent-pulse' : ''}"
		class:loading={checkoutLoading}
		class:disabled={isDisabled}
		disabled={isDisabled}
		on:click={handleOpenCheckout}
		type="button"
	>
		{#if showSpinner}
			<div class="spinner" aria-hidden="true"></div>
		{/if}
		<span class:ml-2={showSpinner}>{displayText}</span>
	</button>

	{#if checkoutError}
		<div class="error-message">
			{checkoutError}
		</div>
	{/if}

	<!-- Checkout Overlay -->
	<CheckoutOverlay
		bind:open={isOverlayOpen}
		initialPlan={planType}
		on:close={handleOverlayClose}
		on:checkout-complete={handleCheckoutComplete}
	/>
{:else}
	<!-- Fallback when payments disabled -->
	<button class="btn-disabled" disabled>
		Payments Not Available
	</button>
{/if}

<style>
	.loading {
		opacity: 0.8;
		cursor: not-allowed;
		position: relative;
	}

	.disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	.spinner {
		display: inline-block;
		width: 16px;
		height: 16px;
		border: 2px solid transparent;
		border-top: 2px solid currentColor;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	.ml-2 {
		margin-left: 0.5rem;
	}

	@keyframes spin {
		0% {
			transform: rotate(0deg);
		}
		100% {
			transform: rotate(360deg);
		}
	}

	.error-message {
		color: #ef4444;
		font-size: 0.875rem;
		margin-top: 0.5rem;
		padding: 0.5rem;
		background-color: #fef2f2;
		border: 1px solid #fecaca;
		border-radius: 0.375rem;
	}

	.btn-disabled {
		background-color: #6b7280;
		color: white;
		padding: 0.5rem 1rem;
		border-radius: 0.375rem;
		border: none;
		cursor: not-allowed;
		opacity: 0.5;
	}

	/* Dark mode error styling */
	:global(.dark) .error-message {
		background-color: #451a03;
		border-color: #7c2d12;
		color: #f87171;
	}

	/* Urgent pulsing animation for critical situations */
	.urgent-pulse {
		animation: urgentPulse 1.5s ease-in-out infinite;
		box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7);
	}

	@keyframes urgentPulse {
		0% {
			transform: scale(1);
			box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7);
		}
		50% {
			transform: scale(1.02);
			box-shadow: 0 0 0 8px rgba(239, 68, 68, 0);
		}
		100% {
			transform: scale(1);
			box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
		}
	}
</style>