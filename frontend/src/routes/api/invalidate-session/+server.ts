import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

// Server-side endpoint to clear HttpOnly session cookies
// This is called when the client detects a 401 and needs to clear the session
export const POST: RequestHandler = async ({ cookies }) => {
	// Clear the session cookie server-side (works for HttpOnly cookies)
	// For deletion, we need to match the original cookie settings exactly
	cookies.delete('id', { path: '/' });

	// Also clear any other session-related cookies with various path/domain combinations
	cookies.delete('session', { path: '/' });

	// Try additional variations that might exist in different environments
	cookies.delete('id', { path: '/', domain: undefined });
	cookies.delete('session', { path: '/', domain: undefined });

	console.log('[invalidate-session] Session cookies cleared server-side');

	return json({ success: true, message: 'Session invalidated' });
};
