<script lang="ts">
	import { resolve } from '$app/paths';
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto as _goto } from '$app/navigation';
	import { PUBLIC_ENABLE_PAYMENTS } from '$env/static/public';

	let transactionId: string | null = null;
	let status: string | null = null;
	let loading = true;
	let error: string | null = null;
	let processingTransaction = false; // Prevent duplicate processing

	onMount(() => {
		// Check if payments are enabled
		if (!PUBLIC_ENABLE_PAYMENTS || PUBLIC_ENABLE_PAYMENTS !== 'true') {
			error = 'Payments are not enabled in this environment';
			loading = false;
			return;
		}

		// Prevent duplicate processing if already processing
		if (processingTransaction) {
			console.log('🔄 Already processing transaction, ignoring duplicate mount');
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

		// Check if this is a placeholder transaction ID that wasn't properly replaced
		const isPlaceholderTransactionId =
			transactionId === '{transaction_id}' ||
			transactionId === 'undefined' ||
			transactionId === 'null';

		if (transactionId && !isPlaceholderTransactionId) {
			// Check if we've already processed this transaction
			const processedKey = `payment_processed_${transactionId}`;
			if (typeof sessionStorage !== 'undefined' && sessionStorage.getItem(processedKey)) {
				console.log('🔄 Transaction already processed, redirecting to main app...');
				loading = false;
				setTimeout(() => {
					_goto(resolve('/'));
				}, 1000);
				return;
			}

			// Valid transaction completion detected
			processingTransaction = true;
			handleTransactionCompletion();
		} else {
			// No valid transaction ID - but payment might still have succeeded
			console.log('No valid transaction ID found, checking subscription status directly...');
			console.log('This is expected behavior - Paddle redirects without transaction parameters');
			processingTransaction = true;
			handleNoTransactionId();
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
			const { subscriptionStore } = await import('$lib/stores/subscription.svelte');

			// Clear subscription cache to ensure we get fresh data
			subscriptionStore.clearCache();

			// Set up subscription change listener for immediate detection
			let _subscriptionDetected = false;
			const unsubscribe = subscriptionStore.onSubscriptionChange((changes) => {
				console.log('🎯 Payment page detected subscription change:', changes);
				if (
					changes.current &&
					(changes.current.status === 'active' || changes.current.status === 'trialing')
				) {
					_subscriptionDetected = true;
					console.log('✅ Active/trialing subscription detected via change listener');
				}
			});

			// Try to verify transaction with backend (with improved retry logic)
			console.log('Verifying transaction with backend...');
			let result;
			let retryCount = 0;
			const maxRetries = 8; // Increased from 3 to 8

			// Smarter retry timing: fast initially, then slower
			const getRetryDelay = (attempt: number): number => {
				if (attempt < 3) return 1000; // First 3: 1s apart
				if (attempt < 6) return 2000; // Next 3: 2s apart
				return 3000; // Final 2: 3s apart
			};

			while (retryCount < maxRetries) {
				result = await apiClient.verifyTransaction(transactionId!);

				console.log(`Verification attempt ${retryCount + 1}/${maxRetries} result:`, result);

				// Check both the response wrapper success AND the data.success field
				if (result.isOk() && result.value?.success === true) {
					// Success - transaction verified
					console.log('✅ Transaction verified successfully');
					break;
				} else if (result.isOk() && result.value?.source === 'database') {
					// Transaction is in our database, treat as success
					console.log('✅ Transaction found in database');
					break;
				} else if (retryCount < maxRetries - 1) {
					const delay = getRetryDelay(retryCount);
					console.log(
						`⏳ Verification attempt ${retryCount + 1} needs retry, waiting ${delay / 1000}s...`
					);
					await new Promise((resolve) => setTimeout(resolve, delay));
					retryCount++;
				} else {
					console.log('⚠️ All verification attempts exhausted');
					break;
				}
			}

			// Clean up subscription listener
			unsubscribe();

			if (
				result &&
				result.isOk() &&
				(result.value?.success === true || result.value?.source === 'database')
			) {
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

				// Force refresh subscription store to update sidebar immediately
				const { subscriptionStore } = await import('$lib/stores/subscription.svelte');
				await subscriptionStore.refresh(true); // Force refresh bypasses cache
				console.log('Subscription store force refreshed after payment success');

				// Mark transaction as processed to prevent duplicate processing
				if (typeof sessionStorage !== 'undefined' && transactionId) {
					sessionStorage.setItem(`payment_processed_${transactionId}`, 'true');
				}

				// Show success message
				error = null;
				loading = false;

				// Redirect to main app after a short delay
				setTimeout(() => {
					_goto(resolve('/'));
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
				if (
					subscription &&
					(subscription.status === 'active' || subscription.status === 'trialing')
				) {
					console.log(`Subscription is ${subscription.status} despite verification failure`);

					// Mark transaction as processed
					if (typeof sessionStorage !== 'undefined' && transactionId) {
						sessionStorage.setItem(`payment_processed_${transactionId}`, 'true');
					}

					error = null;
					loading = false;

					// Redirect to main app
					setTimeout(() => {
						_goto(resolve('/'));
					}, 2000);
				} else {
					// Show error but provide options
					error =
						'Transaction verification is taking longer than expected. Your payment may still be processing.';
					loading = false;
				}
			}
		} catch (err) {
			console.error('Error handling transaction completion:', err);
			error =
				'Unable to verify payment status. Please refresh the page or contact support if the issue persists.';
			loading = false;
		}
	}

	async function handleNoTransactionId() {
		try {
			loading = true;
			error = null;

			// Import necessary modules
			const { subscriptionStore } = await import('$lib/stores/subscription.svelte');

			// Clear subscription cache to ensure fresh data
			subscriptionStore.clearCache();

			// Set up subscription change listener for immediate detection
			let _subscriptionDetected = false;
			const unsubscribe = subscriptionStore.onSubscriptionChange((changes) => {
				console.log('🎯 Payment page (no txn) detected subscription change:', changes);
				if (
					changes.current &&
					(changes.current.status === 'active' || changes.current.status === 'trialing')
				) {
					_subscriptionDetected = true;
					console.log('✅ Active/trialing subscription detected via change listener');
				}
			});

			// Check if user has a subscription now (payment completed but no transaction ID)
			console.log('Checking current subscription status (no transaction ID provided)...');

			// Improved retry logic with better timing
			let retryCount = 0;
			const maxRetries = 8; // Increased from 3 to 8
			let subscription = null;

			// Smarter retry timing
			const getRetryDelay = (attempt: number): number => {
				if (attempt < 3) return 1000; // First 3: 1s apart
				if (attempt < 6) return 2000; // Next 3: 2s apart
				return 3000; // Final 2: 3s apart
			};

			while (retryCount < maxRetries && !subscription) {
				console.log(`🔄 Subscription check attempt ${retryCount + 1}/${maxRetries}...`);
				await subscriptionStore.refresh(true); // Force refresh
				subscription = subscriptionStore.subscription;

				if (
					subscription &&
					(subscription.status === 'active' || subscription.status === 'trialing')
				) {
					console.log('✅ Found active/trialing subscription');
					break;
				}

				if (retryCount < maxRetries - 1) {
					const delay = getRetryDelay(retryCount);
					console.log(`⏳ Subscription not found yet, waiting ${delay / 1000}s before retry...`);
					await new Promise((resolve) => setTimeout(resolve, delay));
					retryCount++;
				} else {
					console.log('⚠️ All subscription check attempts exhausted');
					break;
				}
			}

			// Clean up subscription listener
			unsubscribe();

			if (
				subscription &&
				(subscription.status === 'active' || subscription.status === 'trialing')
			) {
				console.log(`Found ${subscription.status} subscription, payment was likely successful`);

				// Show success message
				loading = false;
				error = null;
				status = 'success'; // Set status for success display

				// Redirect to main app after a short delay
				setTimeout(() => {
					_goto(resolve('/'));
				}, 2000);
			} else {
				// No active subscription found - this might be normal if on the free plan
				console.log('No active subscription found - may be returning to free plan');
				loading = false;
				error =
					'Payment verification completed. If you made a payment, it may take a few minutes to process.';

				// Redirect to main app after a delay
				setTimeout(() => {
					_goto(resolve('/'));
				}, 4000);
			}
		} catch (err) {
			console.error('Error checking subscription status:', err);
			loading = false;
			error = 'Unable to verify payment status. Returning to the app...';

			// Redirect to main app anyway
			setTimeout(() => {
				_goto(resolve('/'));
			}, 3000);
		}
	}

	function handleContinue() {
		// Redirect to dashboard or appropriate page after payment
		_goto(resolve('/'));
	}
</script>

<svelte:head>
	<title>Payment - Sanguine Scribe</title>
	<meta name="description" content="Payment processing and completion" />
</svelte:head>

<div
	class="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800"
>
	<div class="container mx-auto px-4 py-8">
		<div class="mx-auto max-w-md">
			{#if loading}
				<div class="rounded-lg bg-white p-8 text-center shadow-lg dark:bg-slate-800">
					<div
						class="mx-auto mb-4 h-8 w-8 animate-spin rounded-full border-b-2 border-blue-600"
					></div>
					<p class="text-slate-600 dark:text-slate-300">
						{transactionId ? 'Verifying payment...' : 'Checking subscription status...'}
					</p>
					{#if !transactionId}
						<p class="mt-2 text-xs text-slate-500 dark:text-slate-400">
							This may take a few moments while we confirm your payment
						</p>
					{/if}
				</div>
			{:else if error}
				<div class="rounded-lg bg-white p-8 shadow-lg dark:bg-slate-800">
					<div class="text-center">
						<div
							class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-yellow-100 dark:bg-yellow-900/30"
						>
							<svg
								class="h-6 w-6 text-yellow-600 dark:text-yellow-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
								/>
							</svg>
						</div>
						<h1 class="mb-2 text-xl font-semibold text-slate-900 dark:text-slate-100">
							Payment Processing
						</h1>
						<p class="mb-4 text-slate-600 dark:text-slate-300">{error}</p>

						{#if transactionId}
							<p class="mb-6 text-sm text-slate-500 dark:text-slate-400">
								Transaction ID: <code class="rounded bg-slate-100 px-2 py-1 dark:bg-slate-700"
									>{transactionId}</code
								>
							</p>
							<div class="space-y-3">
								<button
									onclick={() => {
										loading = true;
										error = null;
										handleTransactionCompletion();
									}}
									class="w-full rounded-lg bg-blue-600 px-4 py-3 font-medium text-white transition-colors hover:bg-blue-700"
								>
									Retry Verification
								</button>
								<button
									onclick={handleContinue}
									class="w-full rounded-lg bg-slate-200 px-4 py-3 font-medium text-slate-900 transition-colors hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-100 dark:hover:bg-slate-600"
								>
									Continue to App
								</button>
							</div>
						{:else}
							<button
								onclick={handleContinue}
								class="w-full rounded-lg bg-blue-600 px-4 py-3 font-medium text-white transition-colors hover:bg-blue-700"
							>
								Return to App
							</button>
						{/if}
					</div>
				</div>
			{:else if transactionId}
				<div class="rounded-lg bg-white p-8 shadow-lg dark:bg-slate-800">
					<div class="text-center">
						<div
							class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/30"
						>
							<svg
								class="h-6 w-6 text-green-600 dark:text-green-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M5 13l4 4L19 7"
								/>
							</svg>
						</div>
						<h1 class="mb-2 text-xl font-semibold text-slate-900 dark:text-slate-100">
							Payment {status === 'success' ? 'Successful' : 'Processed'}
						</h1>
						<p class="mb-2 text-slate-600 dark:text-slate-300">
							Thank you for your payment! Your transaction has been processed.
						</p>
						<p class="mb-6 text-sm text-slate-500 dark:text-slate-400">
							Transaction ID: <code class="rounded bg-slate-100 px-2 py-1 dark:bg-slate-700"
								>{transactionId}</code
							>
						</p>
						<button
							onclick={handleContinue}
							class="w-full rounded-lg bg-blue-600 px-4 py-3 font-medium text-white transition-colors hover:bg-blue-700"
						>
							Continue to App
						</button>
					</div>
				</div>
			{:else}
				<div class="rounded-lg bg-white p-8 shadow-lg dark:bg-slate-800">
					<div class="text-center">
						<div
							class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900/30"
						>
							<svg
								class="h-6 w-6 text-blue-600 dark:text-blue-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									stroke-linecap="round"
									stroke-linejoin="round"
									stroke-width="2"
									d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
								/>
							</svg>
						</div>
						<h1 class="mb-2 text-xl font-semibold text-slate-900 dark:text-slate-100">
							Payment Portal
						</h1>
						<p class="mb-6 text-slate-600 dark:text-slate-300">
							No payment transaction detected. Redirecting you back to the app...
						</p>
						<button
							onclick={handleContinue}
							class="w-full rounded-lg bg-blue-600 px-4 py-3 font-medium text-white transition-colors hover:bg-blue-700"
						>
							Return to App
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
</div>
