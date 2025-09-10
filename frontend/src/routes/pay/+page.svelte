<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { PUBLIC_ENABLE_PAYMENTS } from '$env/static/public';

	let transactionId: string | null = null;
	let status: string | null = null;
	let loading = true;
	let error: string | null = null;

	onMount(() => {
		// Check if payments are enabled
		if (!PUBLIC_ENABLE_PAYMENTS || PUBLIC_ENABLE_PAYMENTS !== 'true') {
			error = 'Payments are not enabled in this environment';
			loading = false;
			return;
		}

		// Get transaction ID and status from URL parameters
		const urlParams = new URLSearchParams($page.url.search);
		transactionId = urlParams.get('transaction_id') || urlParams.get('_ptxn');
		status = urlParams.get('status');

		if (transactionId) {
			// Transaction completion detected
			handleTransactionCompletion();
		} else {
			// No transaction ID - redirect to main app
			setTimeout(() => {
				goto('/');
			}, 3000);
		}
		
		loading = false;
	});

	async function handleTransactionCompletion() {
		try {
			// Here you could make an API call to verify the transaction status
			// For now, we'll just show the completion message
			console.log('Transaction completed:', transactionId);
			
			// Optional: Verify transaction status with backend
			// const response = await fetch(`/api/payment/transaction/${transactionId}/status`);
			// const data = await response.json();
		} catch (err) {
			console.error('Error handling transaction completion:', err);
			error = 'Failed to process transaction completion';
		}
	}

	function handleContinue() {
		// Redirect to dashboard or appropriate page after payment
		goto('/');
	}
</script>

<svelte:head>
	<title>Payment - Sanguine Scribe</title>
	<meta name="description" content="Payment processing and completion" />
</svelte:head>

<div class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
	<div class="container mx-auto px-4 py-8">
		<div class="max-w-md mx-auto">
			{#if loading}
				<div class="bg-white dark:bg-slate-800 rounded-lg shadow-lg p-8 text-center">
					<div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
					<p class="text-slate-600 dark:text-slate-300">Processing payment...</p>
				</div>
			{:else if error}
				<div class="bg-white dark:bg-slate-800 rounded-lg shadow-lg p-8">
					<div class="text-center">
						<div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
							<svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
							</svg>
						</div>
						<h1 class="text-xl font-semibold text-slate-900 dark:text-slate-100 mb-2">
							Payment Error
						</h1>
						<p class="text-slate-600 dark:text-slate-300 mb-6">{error}</p>
						<button
							on:click={handleContinue}
							class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
						>
							Return to App
						</button>
					</div>
				</div>
			{:else if transactionId}
				<div class="bg-white dark:bg-slate-800 rounded-lg shadow-lg p-8">
					<div class="text-center">
						<div class="w-12 h-12 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
							<svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
							</svg>
						</div>
						<h1 class="text-xl font-semibold text-slate-900 dark:text-slate-100 mb-2">
							Payment {status === 'success' ? 'Successful' : 'Processed'}
						</h1>
						<p class="text-slate-600 dark:text-slate-300 mb-2">
							Thank you for your payment! Your transaction has been processed.
						</p>
						<p class="text-sm text-slate-500 dark:text-slate-400 mb-6">
							Transaction ID: <code class="bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded">{transactionId}</code>
						</p>
						<button
							on:click={handleContinue}
							class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
						>
							Continue to App
						</button>
					</div>
				</div>
			{:else}
				<div class="bg-white dark:bg-slate-800 rounded-lg shadow-lg p-8">
					<div class="text-center">
						<div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
							<svg class="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
							</svg>
						</div>
						<h1 class="text-xl font-semibold text-slate-900 dark:text-slate-100 mb-2">
							Payment Portal
						</h1>
						<p class="text-slate-600 dark:text-slate-300 mb-6">
							No payment transaction detected. Redirecting you back to the app...
						</p>
						<button
							on:click={handleContinue}
							class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
						>
							Return to App
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
</div>