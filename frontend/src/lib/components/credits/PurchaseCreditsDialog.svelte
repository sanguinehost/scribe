<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription
	} from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Alert, AlertDescription } from '$lib/components/ui/alert';
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api';
	import CreditPackageSelector from './CreditPackageSelector.svelte';
	import { AlertCircle, ExternalLink, Loader } from 'lucide-svelte';
	import { ENABLE_PAYMENT_CREDITS } from '$lib/utils/features';
	import type { CreditPackage, PurchaseCreditsResponse } from '$lib/types/payment';

	let { open = $bindable(false) }: { open: boolean } = $props();

	const dispatch = createEventDispatcher<{
		close: void;
		purchaseSuccess: { checkoutUrl: string; transactionId: string };
	}>();

	let selectedPackage: CreditPackage | null = $state(null);
	let isPurchasing = $state(false);
	let purchaseError: string | null = $state(null);


	function handlePackageSelect(pkg: CreditPackage) {
		selectedPackage = pkg;
		purchaseError = null;
	}

	async function handlePurchase() {
		if (!selectedPackage) {
			toast.error('Please select a credit package first');
			return;
		}

		isPurchasing = true;
		purchaseError = null;

		try {
			const result = await apiClient.purchaseCredits(selectedPackage.package_id);

			if (result.isErr()) {
				const error = result.error;
				let errorMessage = 'Failed to start purchase process';

				// Handle specific error types
				if ('status' in error && error.status) {
					switch (error.status) {
						case 401:
							errorMessage = 'Please sign in to purchase credits';
							break;
						case 403:
							errorMessage = 'You do not have permission to purchase credits';
							break;
						case 404:
							errorMessage = 'Selected credit package is no longer available';
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

				purchaseError = errorMessage;
				toast.error(errorMessage);
				return;
			}

			const purchaseData = result.value;

			if (!purchaseData.checkout_url) {
				purchaseError = 'No checkout URL received from payment service';
				toast.error(purchaseError);
				return;
			}

			// Emit success event with purchase data
			dispatch('purchaseSuccess', {
				checkoutUrl: purchaseData.checkout_url,
				transactionId: purchaseData.transaction_id
			});

			toast.success('Redirecting to checkout...');

			// Add a small delay to show the success message
			await new Promise(resolve => setTimeout(resolve, 1000));

			// Redirect to Paddle checkout
			window.location.href = purchaseData.checkout_url;

		} catch (error) {
			const errorMessage = error instanceof Error ? error.message : 'Purchase initialization failed';
			console.error('Purchase error:', errorMessage);
			purchaseError = errorMessage;
			toast.error(errorMessage);
		} finally {
			// Only reset loading if there was an error (successful purchases redirect)
			if (purchaseError) {
				isPurchasing = false;
			}
		}
	}

	function handleClose() {
		if (!isPurchasing) {
			selectedPackage = null;
			purchaseError = null;
			dispatch('close');
		}
	}

	// Format package details for confirmation
	function formatPackageConfirmation(pkg: CreditPackage): string {
		const price = (pkg.price_cents / 100).toFixed(2);
		const credits = pkg.credits.toLocaleString();
		const bonus = pkg.bonus_percentage ? ` (+${pkg.bonus_percentage}% bonus)` : '';
		return `${credits} credits${bonus} for $${price} ${pkg.currency.toUpperCase()}`;
	}
</script>

{#if ENABLE_PAYMENT_CREDITS}
<Dialog bind:open onOpenChange={handleClose}>
	<DialogContent class="sm:max-w-[600px] max-h-[80vh] overflow-y-auto">
		<DialogHeader>
			<DialogTitle>Purchase Credits</DialogTitle>
			<DialogDescription>
				Add credits to your account to continue using premium AI models
			</DialogDescription>
		</DialogHeader>

		<div class="space-y-6 py-4">
			<!-- Package Selection -->
			<CreditPackageSelector
				onPackageSelect={handlePackageSelect}
				selectedPackageId={selectedPackage?.package_id || null}
			/>

			<!-- Purchase Confirmation -->
			{#if selectedPackage}
				<div class="border-t pt-4">
					<h4 class="font-medium mb-3">Purchase Summary</h4>
					<div class="bg-muted/50 rounded-lg p-4 space-y-2">
						<div class="flex justify-between items-center">
							<span class="text-sm text-muted-foreground">Package:</span>
							<span class="font-medium">{selectedPackage.name}</span>
						</div>
						<div class="flex justify-between items-center">
							<span class="text-sm text-muted-foreground">Credits:</span>
							<span class="font-medium">{selectedPackage.credits.toLocaleString()}</span>
						</div>
						{#if selectedPackage.bonus_percentage}
							<div class="flex justify-between items-center">
								<span class="text-sm text-muted-foreground">Bonus:</span>
								<span class="font-medium text-green-600 dark:text-green-400">
									+{selectedPackage.bonus_percentage}%
								</span>
							</div>
						{/if}
						<div class="flex justify-between items-center text-lg font-semibold border-t pt-2">
							<span>Total:</span>
							<span>${(selectedPackage.price_cents / 100).toFixed(2)} {selectedPackage.currency.toUpperCase()}</span>
						</div>
					</div>
				</div>
			{/if}

			<!-- Error Display -->
			{#if purchaseError}
				<Alert variant="destructive">
					<AlertCircle class="h-4 w-4" />
					<AlertDescription>
						{purchaseError}
					</AlertDescription>
				</Alert>
			{/if}

			<!-- Payment Info -->
			<Alert>
				<ExternalLink class="h-4 w-4" />
				<AlertDescription>
					You'll be redirected to our secure payment processor (Paddle) to complete your purchase.
					Your credits will be added to your account immediately after payment confirmation.
				</AlertDescription>
			</Alert>
		</div>

		<!-- Footer Actions -->
		<div class="flex gap-3 pt-4">
			<Button
				variant="outline"
				on:click={handleClose}
				disabled={isPurchasing}
				class="flex-1"
			>
				Cancel
			</Button>
			<Button
				on:click={handlePurchase}
				disabled={!selectedPackage || isPurchasing}
				class="flex-1"
			>
				{#if isPurchasing}
					<Loader class="h-4 w-4 animate-spin mr-2" />
					Processing...
				{:else}
					Continue to Checkout
				{/if}
			</Button>
		</div>
	</DialogContent>
</Dialog>
{/if}