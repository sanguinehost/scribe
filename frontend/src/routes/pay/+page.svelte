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

		// Debug logging to understand what Paddle sends back
		console.log('🎯 PAYMENT SUCCESS PAGE DEBUG:');
		console.log('Full URL:', $page.url.href);
		console.log('Search params:', $page.url.search);

		// Get transaction ID and status from URL parameters
		const urlParams = new URLSearchParams($page.url.search);
		console.log('All URL params:', Object.fromEntries(urlParams.entries()));

		transactionId = urlParams.get('transaction_id') || urlParams.get('_ptxn');
		status = urlParams.get('status');

		console.log('Extracted transaction ID:', transactionId);
		console.log('Extracted status:', status);

		if (transactionId) {
			// Transaction completion detected
			// Don't set loading to false here - let handleTransactionCompletion manage it
			handleTransactionCompletion();
		} else {
			// No transaction ID - redirect to main app
			loading = false;
			setTimeout(() => {
				goto('/');
			}, 3000);
		}
	});

	async function handleTransactionCompletion() {
		try {
			console.log('Transaction completed:', transactionId);

			// Keep loading state true until we're done
			loading = true;

			// Import the API client and auth functions
			const { apiClient } = await import('$lib/api');
			const { setAuthenticated } = await import('$lib/auth.svelte');

			// Try to verify transaction with backend (with retry logic)
			console.log('Verifying transaction with backend...');
			let result;
			let retryCount = 0;
			const maxRetries = 3;
			const retryDelay = 2000; // Start with 2 seconds

			while (retryCount < maxRetries) {
				result = await apiClient.verifyTransaction(transactionId!);

				console.log(`Verification attempt ${retryCount + 1} result:`, result);

				// Check both the response wrapper success AND the data.success field
				if (result.isOk() && result.value?.success === true) {
					// Success - transaction verified
					break;
				} else if (result.isOk() && result.value?.source === 'database') {
					// Transaction is in our database, treat as success
					console.log('Transaction found in database');
					break;
				} else if (retryCount < maxRetries - 1) {
					// Wait before retrying (exponential backoff)
					console.log(`Verification attempt ${retryCount + 1} needs retry, waiting ${retryDelay * (retryCount + 1) / 1000}s...`);
					await new Promise(resolve => setTimeout(resolve, retryDelay * (retryCount + 1)));
					retryCount++;
				} else {
					break;
				}
			}

			if (result && result.isOk() && (result.value?.success === true || result.value?.source === 'database')) {
				console.log('Transaction verified successfully:', result.value);

				// Check if this is a trial subscription
				const isTrial = result.value?.subscription?.status === 'trialing';
				if (isTrial) {
					console.log('Trial subscription activated');
				}

				// Refresh the user data to get updated subscription status
				const userResult = await apiClient.getUser();
				if (userResult.isOk() && userResult.value) {
					// Update the auth state with refreshed user data
					setAuthenticated(userResult.value);
					console.log('User data refreshed with new subscription status');
				}

				// Show success message
				error = null;
				loading = false;

				// Redirect to main app after a short delay
				setTimeout(() => {
					goto('/');
				}, 2000);
			} else {
				// Verification failed after retries - but payment might still be successful
				console.error('Transaction verification failed after retries:', result);

				// Check if we can get subscription status directly
				console.log('Checking subscription status directly...');
				const { subscriptionStore } = await import('$lib/stores/subscription.svelte');
				await subscriptionStore.refresh();

				// If user now has an active or trialing subscription, consider it a success
				const subscription = subscriptionStore.subscription;
				if (subscription && (subscription.status === 'active' || subscription.status === 'trialing')) {
					console.log(`Subscription is ${subscription.status} despite verification failure`);
					error = null;

					// Redirect to main app
					setTimeout(() => {
						goto('/');
					}, 2000);
				} else {
					// Show error but provide options
					error = 'Transaction verification is taking longer than expected. Your payment may still be processing.';
					loading = false;
				}
			}
		} catch (err) {
			console.error('Error handling transaction completion:', err);
			error = 'Unable to verify payment status. Please refresh the page or contact support if the issue persists.';
			loading = false;
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
						<div class="w-12 h-12 bg-yellow-100 dark:bg-yellow-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
							<svg class="w-6 h-6 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
							</svg>
						</div>
						<h1 class="text-xl font-semibold text-slate-900 dark:text-slate-100 mb-2">
							Payment Processing
						</h1>
						<p class="text-slate-600 dark:text-slate-300 mb-4">{error}</p>

						{#if transactionId}
							<p class="text-sm text-slate-500 dark:text-slate-400 mb-6">
								Transaction ID: <code class="bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded">{transactionId}</code>
							</p>
							<div class="space-y-3">
								<button
									on:click={() => {
										loading = true;
										error = null;
										handleTransactionCompletion();
									}}
									class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
								>
									Retry Verification
								</button>
								<button
									on:click={handleContinue}
									class="w-full bg-slate-200 hover:bg-slate-300 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-900 dark:text-slate-100 font-medium py-3 px-4 rounded-lg transition-colors"
								>
									Continue to App
								</button>
							</div>
						{:else}
							<button
								on:click={handleContinue}
								class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
							>
								Return to App
							</button>
						{/if}
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