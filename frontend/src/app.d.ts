// See https://kit.svelte.dev/docs/types#app
// for information about these interfaces
import type { Session, User as _User } from '$lib/types';

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
	interface PaddleEventData {
		name: string;
		data: Record<string, unknown>;
	}

	interface Window {
		Paddle?: {
			Initialize: (config: {
				token: string;
				pwCustomer?: Record<string, unknown>;
				checkout?: {
					settings?: {
						displayMode?: 'overlay' | 'inline';
						theme?: 'light' | 'dark';
						locale?: string;
						variant?: 'one-page' | 'multi-step';
						allowLogout?: boolean;
						frameStyle?: string;
					};
				};
				eventCallback?: (_event: PaddleEventData) => void;
			}) => void;
			Checkout: {
				open: (options: {
					items: Array<{ priceId: string; quantity: number }>;
					successUrl?: string;
					customData?: Record<string, unknown>;
					settings?: Record<string, unknown>;
				}) => void;
			};
		};
	}
}

declare module '$env/static/private' {
	export const DATABASE_URL: string;
}

export {};
