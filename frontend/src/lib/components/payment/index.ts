// Payment component exports
export { default as PaddleLoader } from './PaddleLoader.svelte';
export { default as CheckoutButton } from './CheckoutButton.svelte';
export { default as CheckoutOverlay } from './CheckoutOverlay.svelte';

// Payment types
export interface PaymentPlan {
	id: string;
	name: string;
	price: number;
	currency: string;
	interval: 'monthly' | 'yearly';
	features: string[];
	popular?: boolean;
}

