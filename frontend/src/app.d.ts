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
}

declare module '$env/static/private' {
	export const DATABASE_URL: string;
}

export {};
