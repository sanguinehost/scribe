// Payment component exports
export { default as PaddleLoader } from './PaddleLoader.svelte';
export { default as CheckoutButton } from './CheckoutButton.svelte';

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

// Paddle types for TypeScript support
declare global {
	interface Window {
		Paddle?: {
			Initialize: (config: { environment: 'sandbox' | 'production' }) => void;
			Checkout: {
				open: (options: {
					items: Array<{ priceId: string; quantity: number }>;
					successUrl?: string;
					customData?: Record<string, any>;
				}) => void;
			};
		} | undefined;
	}
}