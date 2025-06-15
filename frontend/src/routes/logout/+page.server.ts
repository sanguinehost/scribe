import { redirect } from '@sveltejs/kit';
import type { PageServerLoad, Actions } from './$types';
import { env } from '$env/dynamic/public';

export const load: PageServerLoad = async ({ cookies, fetch }) => {
	// Call backend logout API
	const sessionCookie = cookies.get('id');
	if (sessionCookie) {
		try {
			const baseUrl = (env.PUBLIC_API_URL || '').trim();
			const logoutUrl = baseUrl ? `${baseUrl}/api/auth/logout` : '/api/auth/logout';
			await fetch(logoutUrl, {
				method: 'POST',
				headers: {
					Cookie: `id=${sessionCookie}`
				}
			});
		} catch (error) {
			// If backend logout fails, still clear the cookie locally
			console.error('Backend logout failed:', error);
		}
	}

	// Clear the session cookie
	cookies.delete('id', { path: '/' });

	// Redirect to signin
	throw redirect(303, '/signin');
};

export const actions: Actions = {
	default: async ({ cookies, fetch }) => {
		// Same logic as load for POST requests
		const sessionCookie = cookies.get('id');
		if (sessionCookie) {
			try {
				const baseUrl = (env.PUBLIC_API_URL || '').trim();
				const logoutUrl = baseUrl ? `${baseUrl}/api/auth/logout` : '/api/auth/logout';
				await fetch(logoutUrl, {
					method: 'POST',
					headers: {
						Cookie: `id=${sessionCookie}`
					}
				});
			} catch (error) {
				console.error('Backend logout failed:', error);
			}
		}

		cookies.delete('id', { path: '/' });
		throw redirect(303, '/signin');
	}
};
