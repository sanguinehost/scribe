import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from '@oslojs/encoding';
import { sha256 } from '@oslojs/crypto/sha2';
import type { Session, User } from '$lib/types';
import { apiClient } from '$lib/api';
import { ResultAsync, fromPromise } from 'neverthrow';
import type { ApiError } from '$lib/errors/api';
import type { Cookies, RequestEvent } from '@sveltejs/kit';
import { ApiResponseError } from '$lib/errors/api';

export function generateSessionToken(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	const token = encodeBase32LowerCaseNoPadding(bytes);
	return token;
}

export function createSession(
	token: string,
	userId: string,
	fetchFn: typeof fetch = globalThis.fetch
): ResultAsync<Session, ApiError> {
	return fromPromise(
		(async () => {
			const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
			const session: Session = {
				id: sessionId,
				user_id: userId,
				expires_at: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString()
			};

			const result = await apiClient.createSession(session, fetchFn);
			if (result.isErr()) {
				throw result.error;
			}

			return session;
		})(),
		(e) => e as ApiError
	);
}

export function validateSessionToken(
	_token: string,
	fetchFn: typeof fetch = globalThis.fetch
): ResultAsync<SessionValidationResult, ApiError> {
	console.log(`[${new Date().toISOString()}] validateSessionToken: ENTER`);
	return fromPromise(
		(async () => {
			// The '_token' parameter is now unused in this function's logic
			// as session validation relies on cookies being sent by fetchFn.

			// Use fetchFn to avoid errors with server-side relative URLs
			console.log(`[${new Date().toISOString()}] validateSessionToken: Fetching current session`);
			const sessionResult = await apiClient.getSession(fetchFn);

			// Explicitly check for errors BEFORE accessing .value
			if (sessionResult.isErr()) {
				const apiError = sessionResult.error;
				// Check if the error is specifically an ApiResponseError with status 404 (Not Found) or 401 (Unauthorized)
				if (
					apiError instanceof ApiResponseError &&
					(apiError.statusCode === 404 || apiError.statusCode === 401)
				) {
					console.log(
						`[${new Date().toISOString()}] validateSessionToken: Session not found or unauthorized (${apiError.statusCode}). Treating as logged out.`
					);
					console.log(
						`[${new Date().toISOString()}] validateSessionToken: EXIT - not found or unauthorized`
					);
					return { session: null, user: null } as const; // Return success with null session/user
				} else {
					// For Network errors or other API response errors, re-throw it to be caught by the fromPromise error handler
					console.error(
						`[${new Date().toISOString()}] validateSessionToken: API error fetching session`,
						apiError
					);
					throw apiError;
				}
			}
			// If we reach here, sessionResult is Ok
			console.log(
				`[${new Date().toISOString()}] validateSessionToken: Session fetched successfully`
			);

			const backendResponse = sessionResult.value;

			// Convert backend session format to our expected format
			const session: Session = {
				id: backendResponse.session.id,
				user_id: backendResponse.session.user_id,
				expires_at:
					typeof backendResponse.session.expires_at === 'string'
						? backendResponse.session.expires_at
						: backendResponse.session.expires_at.toISOString()
			};

			if (Date.now() >= new Date(session.expires_at).getTime()) {
				console.log(
					`[${new Date().toISOString()}] validateSessionToken: Session ${session.id} expired, deleting`
				);
				await apiClient.deleteSession(session.id, fetchFn).catch((error) => {
					console.error('Failed to delete expired session:', error);
				});
				console.log(`[${new Date().toISOString()}] validateSessionToken: EXIT - expired`);
				return { session: null, user: null } as const;
			}

			console.log(
				`[${new Date().toISOString()}] validateSessionToken: EXIT - valid session for user ${backendResponse.user?.user_id}`
			);
			return {
				session,
				user: backendResponse.user
			};
		})(),
		(e) => {
			// This now only catches errors *not* handled above (non-404 API errors, network errors, unexpected exceptions)
			console.error(
				`[${new Date().toISOString()}] validateSessionToken: EXIT - Error in promise`,
				e
			);
			return e as ApiError;
		}
	);
}

export function invalidateSession(
	sessionId: string,
	fetchFn: typeof fetch = globalThis.fetch
): ResultAsync<undefined, ApiError> {
	return fromPromise(
		(async () => {
			const result = await apiClient.deleteSession(sessionId, fetchFn);
			if (result.isErr()) {
				throw result.error;
			}
			return undefined;
		})(),
		(e) => e as ApiError
	);
}

export function invalidateAllSessions(
	userId: string,
	fetchFn: typeof fetch = globalThis.fetch
): ResultAsync<undefined, ApiError> {
	return fromPromise(
		(async () => {
			const result = await apiClient.deleteSessionsForUser(userId, fetchFn);
			if (result.isErr()) {
				throw result.error;
			}
			return undefined;
		})(),
		(e) => e as ApiError
	);
}

export function getSessionCookie(event: RequestEvent): string | undefined {
	return event.cookies.get('session');
}

export function setSessionTokenCookie(cookies: Cookies, token: string, expiresAt: Date): void {
	cookies.set('session', token, {
		httpOnly: true,
		sameSite: 'lax',
		expires: expiresAt,
		path: '/',
		secure: true // Ensure cookie is only sent over HTTPS
	});
}

export function deleteSessionTokenCookie(cookies: Cookies): void {
	cookies.set('session', 'token', {
		httpOnly: true,
		sameSite: 'lax',
		maxAge: 0,
		path: '/'
	});
}

export type SessionValidationResult =
	| { session: Session; user: User }
	| { session: null; user: null };
