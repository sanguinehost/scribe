<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { browser } from '$app/environment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { apiClient } from '$lib/api';
	import type { PlanType } from '$lib/types';

	// Props
	export let planType: string = 'pro';
	export let disabled: boolean = false;
	export let loading: boolean = false;
	export let buttonText: string = 'Subscribe';
	export let buttonClass: string = 'btn-primary';
	export let urgent: boolean = false; // Add urgent styling for critical situations

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
				throw new Error('Payment system not ready. Please refresh the page and try again.');
			}

			// Create payment transaction via our API using the apiClient
			const result = await apiClient.createPayment({
				plan_type: planType as PlanType,
				success_url: `${window.location.origin}/pay?transaction_id={transaction_id}`,
				cancel_url: window.location.href // Return to current page on cancel
			});

			// Handle API client errors
			if (result.isErr()) {
				const error = result.error;
				let errorMessage = 'Failed to create payment';
				
				// Handle specific error types from API client
				if ('status' in error && error.status) {
					switch (error.status) {
						case 401:
							errorMessage = 'Please sign in to upgrade your plan';
							break;
						case 403:
							errorMessage = 'You do not have permission to create a subscription';
							break;
						case 429:
							errorMessage = 'Too many requests. Please try again in a moment';
							break;
						case 500:
							errorMessage = 'Server error. Please try again later';
							break;
						default:
							errorMessage = `Payment service error (${error.status})`;
					}
				} else {
					errorMessage = error.message || errorMessage;
				}
				
				throw new Error(errorMessage);
			}

			const paymentData = result.value;
			const checkoutUrl = paymentData.checkout_url;

			if (!checkoutUrl) {
				throw new Error('No checkout URL returned from payment service');
			}

			dispatch('checkout-success', { checkoutUrl });

			// Add a small delay to show the "Redirecting..." state
			await new Promise(resolve => setTimeout(resolve, 500));

			// Redirect to Paddle checkout
			window.location.href = checkoutUrl;

		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Payment initialization failed';
			console.error('Checkout error:', errorMessage);
			checkoutError = errorMessage;
			dispatch('checkout-error', { error: errorMessage });
		} finally {
			// Only reset loading if we're not redirecting (in case of error)
			if (checkoutError) {
				checkoutLoading = false;
			}
		}
	}

	// Determine if button should be disabled
	$: isDisabled = disabled || loading || checkoutLoading || !ENABLE_PAYMENTS;
	$: displayText = checkoutLoading ? 'Redirecting to checkout...' : loading ? 'Loading...' : buttonText;
	$: showSpinner = checkoutLoading || loading;
</script>

{#if ENABLE_PAYMENTS}
	<button
		class="{buttonClass} {urgent ? 'urgent-pulse' : ''}"
		class:loading={checkoutLoading}
		class:disabled={isDisabled}
		disabled={isDisabled}
		on:click={handleCheckout}
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