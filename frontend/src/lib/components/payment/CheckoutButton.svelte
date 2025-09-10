<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { apiClient } from '$lib/api';

	// Props
	export let planType: string = 'pro';
	export let disabled: boolean = false;
	export let loading: boolean = false;
	export let buttonText: string = 'Subscribe';
	export let buttonClass: string = 'btn-primary';

	// State
	let checkoutLoading = false;
	let checkoutError: string | null = null;

	const dispatch = createEventDispatcher<{
		'checkout-start': { planType: string };
		'checkout-success': { checkoutUrl: string };
		'checkout-error': { error: string };
	}>();

	/**
	 * Initiate Paddle checkout flow
	 */
	async function handleCheckout() {
		if (!browser || !ENABLE_PAYMENTS || disabled || loading) {
			return;
		}

		checkoutLoading = true;
		checkoutError = null;

		dispatch('checkout-start', { planType });

		try {
			// Check if Paddle is loaded
			if (!window.Paddle) {
				throw new Error('Paddle.js not loaded. Please refresh the page.');
			}

			// Create payment transaction via our API using fetch directly
			const response = await fetch('/api/payment/payment', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				credentials: 'include',
				body: JSON.stringify({
					plan_type: planType,
					success_url: `${window.location.origin}/pay`,
					cancel_url: `${window.location.origin}/pricing`
				})
			});

			if (!response.ok) {
				const errorData = await response.json();
				throw new Error(errorData.message || 'Failed to create payment');
			}

			const paymentData = await response.json();
			const checkoutUrl = paymentData.checkout_url;

			if (!checkoutUrl) {
				throw new Error('No checkout URL returned from payment service');
			}

			dispatch('checkout-success', { checkoutUrl });

			// Redirect to Paddle checkout
			window.location.href = checkoutUrl;

		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Payment initialization failed';
			console.error('Checkout error:', errorMessage);
			checkoutError = errorMessage;
			dispatch('checkout-error', { error: errorMessage });
		} finally {
			checkoutLoading = false;
		}
	}

	// Determine if button should be disabled
	$: isDisabled = disabled || loading || checkoutLoading || !ENABLE_PAYMENTS;
	$: displayText = checkoutLoading ? 'Redirecting...' : loading ? 'Loading...' : buttonText;
</script>

{#if ENABLE_PAYMENTS}
	<button
		class={buttonClass}
		class:loading={checkoutLoading}
		class:disabled={isDisabled}
		disabled={isDisabled}
		on:click={handleCheckout}
		type="button"
	>
		{displayText}
	</button>

	{#if checkoutError}
		<div class="error-message">
			{checkoutError}
		</div>
	{/if}
{:else}
	<!-- Fallback when payments disabled -->
	<button class="btn-disabled" disabled>
		Payments Not Available
	</button>
{/if}

<style>
	.loading {
		opacity: 0.6;
		cursor: not-allowed;
	}
	
	.disabled {
		opacity: 0.4;
		cursor: not-allowed;
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
</style>