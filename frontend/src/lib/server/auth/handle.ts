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
			console.log(`[${new Date().toISOString()}] handle: Session valid, setting locals for user ${user.id}`);
			setSessionTokenCookie(event.cookies, token, session.expiresAt);
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
