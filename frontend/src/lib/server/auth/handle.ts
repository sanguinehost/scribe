import type { Handle } from '@sveltejs/kit';
import {
	deleteSessionTokenCookie,
	getSessionCookie,
	setSessionTokenCookie,
	validateSessionToken
} from '.';

export const handle: Handle = async ({ event, resolve }) => {
	console.log(`[${new Date().toISOString()}] handle: ENTER - path=${event.url.pathname} isSubRequest=${event.isSubRequest}`);

	// If this is an internal fetch (e.g., from validateSessionToken calling apiClient),
	// skip auth handling to prevent recursion. The original request that triggered
	// this fetch will have already set event.locals.
	if (event.isSubRequest) {
		console.log(`[${new Date().toISOString()}] handle: EXIT - Skipping auth for sub-request`);
		return resolve(event);
	}

	// Proceed with auth handling only for top-level requests
	const token = getSessionCookie(event);
	if (!token) {
		console.log(`[${new Date().toISOString()}] handle: EXIT - no token`);
		return resolve(event);
	}

	const validatedTokenResult = await validateSessionToken(token, event.fetch);
	if (validatedTokenResult.isErr()) {
		console.error(`[${new Date().toISOString()}] handle: Session validation error:`, validatedTokenResult.error);
		deleteSessionTokenCookie(event.cookies);
	} else {
		const { session, user } = validatedTokenResult.value;
		if (session && user) {
			console.log(`[${new Date().toISOString()}] handle: Inside if block. typeof user: ${typeof user}, Object.keys(user): ${Object.keys(user).join(', ')}, user:`, JSON.stringify(user));
			try {
				const userId = user.user_id;
				console.log(`[${new Date().toISOString()}] handle: Successfully accessed user.user_id: ${userId}`);
			} catch (e: unknown) {
				if (e instanceof Error) {
					console.error(`[${new Date().toISOString()}] handle: Error accessing user.user_id:`, e.message);
				} else {
					console.error(`[${new Date().toISOString()}] handle: Unknown error accessing user.user_id:`, e);
				}
			}

			console.log(`[${new Date().toISOString()}] handle: Session valid, setting locals for user ${user.user_id}`);
			setSessionTokenCookie(event.cookies, token, session.expires_at);
			event.locals.session = session;
			event.locals.user = user;
		} else {
			console.log(`[${new Date().toISOString()}] handle: Session invalid/expired/not found, deleting cookie`);
			deleteSessionTokenCookie(event.cookies);
		}
	}

	console.log(`[${new Date().toISOString()}] handle: EXIT - resolving top-level request`);
	return resolve(event);
};
