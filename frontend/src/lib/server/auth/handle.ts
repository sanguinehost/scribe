import type { Handle } from '@sveltejs/kit';
// Unused imports after simplification:
// import {
// 	deleteSessionTokenCookie,
// 	getSessionCookie,
// 	setSessionTokenCookie,
// 	validateSessionToken
// } from '.';

export const handle: Handle = async ({ event, resolve }) => {
	const timestamp = new Date().toISOString();
	console.log(
		`[${timestamp}] handle: ENTER - path=${event.url.pathname}, isSubRequest=${event.isSubRequest}`
	);

	// If this is an internal fetch (e.g., from a load function calling an internal endpoint,
	// or a fetch initiated by the SvelteKit framework itself), skip custom handling.
	// The original top-level request would have already been processed.
	if (event.isSubRequest) {
		console.log(`[${timestamp}] handle: EXIT - Skipping for sub-request`);
		return resolve(event);
	}

	// In the new architecture, this server hook no longer proactively validates sessions
	// by making API calls to the backend. Authentication is primarily determined by the
	// backend (Axum with axum-login) through HttpOnly session cookies.
	//
	// Client-side logic will manage its perception of auth state (e.g., in a Svelte store)
	// based on API responses (e.g., 401 Unauthorized).
	//
	// `event.locals.user` and `event.locals.session` will only be populated if an
	// upstream mechanism (e.g., a SvelteKit adapter deeply integrated with the Axum
	// backend's session management) has already done so before this hook runs.
	// Otherwise, they will remain undefined here, which is expected for a more
	// client-centric auth flow or if server-side `load` functions are to make their
	// own auth checks via API calls to protected endpoints.

	// For debugging, let's see if event.locals.user is populated by anything upstream.
	if (event.locals.user) {
		// Ensure user_id exists before trying to log it, to prevent errors if user is an unexpected shape.
		const userId =
			typeof event.locals.user === 'object' &&
			event.locals.user !== null &&
			'user_id' in event.locals.user
				? (event.locals.user as { user_id: string }).user_id
				: 'unknown';
		console.log(`[${timestamp}] handle: User found in event.locals. User ID: ${userId}`);
	} else {
		console.log(
			`[${timestamp}] handle: No user found in event.locals prior to this hook's main logic.`
		);
	}

	// For non-API requests, validate session and set user in locals for SSR
	if (!event.url.pathname.startsWith('/api/')) {
		const sessionCookie = event.cookies.get('session');
		if (sessionCookie) {
			try {
				// Validate session with backend
				const response = await event.fetch('/api/auth/me', {
					headers: {
						Cookie: `session=${sessionCookie}`
					}
				});

				if (response.ok) {
					const user = await response.json();
					event.locals.user = user;
					console.log(
						`[${timestamp}] handle: Session validated, user set in locals:`,
						user.username
					);
				} else {
					console.log(
						`[${timestamp}] handle: Session validation failed with status ${response.status}`
					);
					// Don't clear the cookie here - let the client handle 401s
				}
			} catch (error) {
				console.log(`[${timestamp}] handle: Session validation error:`, error);
				// Don't clear the cookie here - could be temporary network issue
			}
		}
	}

	console.log(
		`[${timestamp}] handle: EXIT - resolving request, user in locals:`,
		!!event.locals.user
	);
	return resolve(event);
};
