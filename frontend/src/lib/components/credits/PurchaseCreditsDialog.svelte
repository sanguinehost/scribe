<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { browser } from '$app/environment';
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription
	} from '$lib/components/ui/dialog';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Alert, AlertDescription } from '$lib/components/ui/alert';
	import { toast } from 'svelte-sonner';
	import CreditPackageSelector from './CreditPackageSelector.svelte';
	import { AlertCircle, ExternalLink, Loader } from 'lucide-svelte';
	import { ENABLE_PAYMENT_CREDITS } from '$lib/utils/features';
	import { PUBLIC_PADDLE_CLIENT_SIDE_TOKEN } from '$env/static/public';
	import type { CreditPackage } from '$lib/types/payment';

	let { open = $bindable(false) }: { open: boolean } = $props();

	const dispatch = createEventDispatcher<{
		close: void;
		checkoutStart: { packageId: string };
		checkoutComplete: { transactionId: string };
	}>();

	let selectedPackage: CreditPackage | null = $state(null);
	let isPurchasing = $state(false);
	let purchaseError: string | null = $state(null);

	function handlePackageSelect(pkg: CreditPackage) {
		selectedPackage = pkg;
		purchaseError = null;
	}

	async function handlePurchase() {
		if (!browser || !ENABLE_PAYMENT_CREDITS || isPurchasing) {
			return;
		}

		if (!selectedPackage) {
			toast.error('Please select a credit package first');
			return;
		}

		// Validate package has Paddle price ID
		if (!selectedPackage.paddle_price_id) {
			purchaseError = 'This credit package is not configured for purchase';
			toast.error(purchaseError);
			return;
		}

		isPurchasing = true;
		purchaseError = null;

		try {
			// Check if Paddle is loaded and initialized
			if (!window.Paddle) {
				throw new Error('Payment system not ready. Please refresh the page and try again.');
			}

			if (!window.Paddle.Checkout || typeof window.Paddle.Checkout.open !== 'function') {
				throw new Error(
					'Payment system not properly initialized. Please refresh the page and try again.'
				);
			}

			// Detect theme for checkout
			const isDarkMode = document.documentElement.classList.contains('dark');
			const theme = isDarkMode ? 'dark' : 'light';

			// Log for debugging in sandbox
			console.log('Opening Paddle checkout for credits:', {
				package: selectedPackage.name,
				packageId: selectedPackage.package_id,
				priceId: selectedPackage.paddle_price_id,
				theme: theme
			});

			// Note for sandbox testing
			if (PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.startsWith('test_')) {
				console.log(
					'🧪 Sandbox Mode - Use test cards: 4242 4242 4242 4242 (Visa) or 4000 0566 5566 5556 (Visa Debit)'
				);
			}

			// Emit event before opening checkout
			dispatch('checkoutStart', { packageId: selectedPackage.package_id });

			// Close our dialog first to avoid z-index conflicts with Paddle overlay
			open = false;
			dispatch('close');

			// Open Paddle checkout overlay
			window.Paddle.Checkout.open({
				items: [
					{
						priceId: selectedPackage.paddle_price_id,
						quantity: 1
					}
				],
				settings: {
					displayMode: 'overlay',
					theme: theme,
					locale: navigator.language?.substring(0, 2) || 'en',
					variant: 'one-page',
					allowLogout: false
				},
				customData: {
					package_id: selectedPackage.package_id,
					credits: selectedPackage.credits,
					source: 'purchase_credits_dialog',
					version: '1.0'
				}
			});

			// Reset state after successful checkout open
			isPurchasing = false;
		} catch (_error) {
			const errorMessage =
				_error instanceof Error ? _error.message : 'Payment initialization failed';
			console.error('❌ Credit purchase error:', {
				error: _error,
				message: errorMessage,
				package: selectedPackage.package_id,
				priceId: selectedPackage.paddle_price_id,
				paddleLoaded: !!window.Paddle,
				paddleCheckout: !!window.Paddle?.Checkout,
				token: PUBLIC_PADDLE_CLIENT_SIDE_TOKEN?.substring(0, 8) + '...'
			});
			purchaseError = errorMessage;
			toast.error(errorMessage);
			isPurchasing = false;
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
	function _formatPackageConfirmation(pkg: CreditPackage): string {
		const price = (pkg.price_cents / 100).toFixed(2);
		const credits = pkg.credits.toLocaleString();
		const bonus = pkg.bonus_percentage ? ` (+${pkg.bonus_percentage}% bonus)` : '';
		return `${credits} credits${bonus} for $${price} ${(pkg.currency || 'USD').toUpperCase()}`;
	}
</script>

{#if ENABLE_PAYMENT_CREDITS}
	<Dialog bind:open onOpenChange={handleClose}>
		<DialogContent class="max-h-[80vh] overflow-y-auto sm:max-w-[600px]">
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
						<h4 class="mb-3 font-medium">Purchase Summary</h4>
						<div class="space-y-2 rounded-lg bg-muted/50 p-4">
							<div class="flex items-center justify-between">
								<span class="text-sm text-muted-foreground">Package:</span>
								<span class="font-medium">{selectedPackage.name}</span>
							</div>
							<div class="flex items-center justify-between">
								<span class="text-sm text-muted-foreground">Credits:</span>
								<span class="font-medium">{selectedPackage.credits.toLocaleString()}</span>
							</div>
							{#if selectedPackage.bonus_percentage}
								<div class="flex items-center justify-between">
									<span class="text-sm text-muted-foreground">Bonus:</span>
									<span class="font-medium text-green-600 dark:text-green-400">
										+{selectedPackage.bonus_percentage}%
									</span>
								</div>
							{/if}
							<div class="flex items-center justify-between border-t pt-2 text-lg font-semibold">
								<span>Total:</span>
								<span
									>${(selectedPackage.price_cents / 100).toFixed(2)}
									{(selectedPackage.currency || 'USD').toUpperCase()}</span
								>
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
						A secure payment overlay will open to complete your purchase. Your credits will be added
						to your account immediately after payment confirmation.
					</AlertDescription>
				</Alert>
			</div>

			<!-- Footer Actions -->
			<div class="flex gap-3 pt-4">
				<ButtonComponent
					variant="outline"
					onclick={handleClose}
					disabled={isPurchasing}
					class="flex-1"
				>
					Cancel
				</ButtonComponent>
				<ButtonComponent
					onclick={handlePurchase}
					disabled={!selectedPackage || isPurchasing}
					class="flex-1"
				>
					{#if isPurchasing}
						<Loader class="mr-2 h-4 w-4 animate-spin" />
						Processing...
					{:else}
						Continue to Checkout
					{/if}
				</ButtonComponent>
			</div>
		</DialogContent>
	</Dialog>
{/if}
