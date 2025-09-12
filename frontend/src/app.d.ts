// See https://kit.svelte.dev/docs/types#app
// for information about these interfaces
import type { Session, User } from '$lib/types';

declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			session?: Session;
			user?: User;
		}
		// interface PageData {}
		// interface Platform {}
	}

	// Paddle.js types
	interface Window {
		Paddle?: {
			Initialize: (config: { 
				token: string;
				pwCustomer?: Record<string, any>;
			}) => void;
			Checkout: {
				open: (options: {
					items: Array<{ priceId: string; quantity: number }>;
					successUrl?: string;
					customData?: Record<string, any>;
				}) => void;
			};
		};
	}
}

declare module '$env/static/private' {
	export const DATABASE_URL: string;
}

export {};
