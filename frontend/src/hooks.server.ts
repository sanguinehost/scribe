// CRITICAL: Import static env FIRST before any other imports
// This is safe because it's baked at build time
import { PUBLIC_ENVIRONMENT } from '$env/static/public';
import type { Handle, HandleFetch } from '@sveltejs/kit';

console.log('[hooks.server.ts] File loaded! PUBLIC_ENVIRONMENT:', PUBLIC_ENVIRONMENT);

// Check if we're in desktop mode - this prevents loading server-side modules in browser
const isDesktop = PUBLIC_ENVIRONMENT === 'desktop';
console.log('[hooks.server.ts] isDesktop:', isDesktop);

// Declare functions that will be conditionally assigned
let handle: Handle;
let handleFetch: HandleFetch;

// Desktop mode: Use no-op functions that do nothing
// These run entirely in the browser and don't need Node.js runtime
if (isDesktop) {
	handle = async ({ event, resolve }) => {
		console.log('[hooks.server.ts] DESKTOP handle() called for:', event.url.toString());
		// Just pass through - no server-side auth in desktop mode
		return resolve(event);
	};

	handleFetch = async ({ request, fetch }) => {
		console.log('[hooks.server.ts] DESKTOP handleFetch() called for:', request.url);
		// Just pass through - no cookie forwarding needed in desktop mode
		return fetch(request);
	};
} else {
	// Cloud mode: Load server-side modules dynamically
	// This code only runs when there's a Node.js runtime available
	const { sequence } = await import('@sveltejs/kit/hooks');
	const { handle: authHandle } = await import('$lib/server/auth/handle');
	const { env } = await import('$env/dynamic/public');

	handle = sequence(authHandle);

	handleFetch = async ({ event, request, fetch }) => {
		// Add debug logging for production debugging
		console.log(`[${new Date().toISOString()}] handleFetch: Processing request`, {
			url: request.url,
			method: request.method,
			headers: Object.fromEntries(request.headers.entries()),
			eventUrl: event.url.toString(),
			eventCookies: event.request.headers.get('cookie')
		});

		// Check if this is an API request (either to production backend or local proxy)
		const isProductionAPI = env.PUBLIC_API_URL && request.url.startsWith(env.PUBLIC_API_URL);
		const isLocalAPI =
			!env.PUBLIC_API_URL &&
			(request.url.includes('localhost') || request.url.startsWith(event.url.origin + '/api'));

		if (isProductionAPI || isLocalAPI) {
			console.log(`[${new Date().toISOString()}] handleFetch: Forwarding cookies to API`);

			// Get cookies from the original request
			const cookies = event.request.headers.get('cookie');
			if (cookies) {
				console.log(
					`[${new Date().toISOString()}] handleFetch: Adding cookies to request:`,
					cookies
				);
				request.headers.set('cookie', cookies);
			} else {
				console.log(`[${new Date().toISOString()}] handleFetch: No cookies found to forward`);
			}
		}

		const response = await fetch(request);

		// Log response details
		console.log(`[${new Date().toISOString()}] handleFetch: Response received`, {
			url: request.url,
			status: response.status,
			headers: Object.fromEntries(response.headers.entries()),
			ok: response.ok
		});

		// Forward Set-Cookie headers from API responses to the browser
		if (isProductionAPI || isLocalAPI) {
			const setCookieHeaders = response.headers.getSetCookie?.() || [];
			console.log(
				`[${new Date().toISOString()}] handleFetch: Processing ${setCookieHeaders.length} Set-Cookie headers`
			);
			console.log(
				`[${new Date().toISOString()}] handleFetch: Raw response headers:`,
				Object.fromEntries(response.headers.entries())
			);

			for (const cookieHeader of setCookieHeaders) {
				console.log(
					`[${new Date().toISOString()}] handleFetch: Raw cookie header:`,
					JSON.stringify(cookieHeader)
				);

				// Parse cookie header: "name=value; Domain=...; Path=...; etc"
				const [nameValue, ...attributes] = cookieHeader.split(';').map((s) => s.trim());
				const [name, value] = nameValue.split('=', 2);

				if (name && value !== undefined) {
					// Parse cookie attributes
					const cookieOptions: {
						path: string; // Required by SvelteKit
						domain?: string;
						maxAge?: number;
						expires?: Date;
						secure?: boolean;
						httpOnly?: boolean;
						sameSite?: 'strict' | 'lax' | 'none';
					} = {
						path: '/' // Default value
					};

					for (const attr of attributes) {
						const [key, val] = attr.split('=', 2);
						const lowerKey = key.toLowerCase();

						switch (lowerKey) {
							case 'domain':
								// In local development, don't set domain attribute to allow localhost cookies
								if (!env.PUBLIC_API_URL) {
									// Skip domain setting for local development
									break;
								}
								// In production, convert API domain to frontend domain for cross-subdomain cookies
								if (val === 'api.staging.scribe.sanguinehost.com') {
									cookieOptions.domain = 'staging.scribe.sanguinehost.com';
								} else if (val === '.staging.scribe.sanguinehost.com') {
									cookieOptions.domain = val; // Keep wildcard domain
								} else if (val) {
									// For any other explicit domain, keep it as-is
									cookieOptions.domain = val;
								}
								// If no domain is specified by backend, don't set one (default behavior)
								break;
							case 'path':
								cookieOptions.path = val || '/';
								break;
							case 'maxage':
								cookieOptions.maxAge = parseInt(val);
								break;
							case 'expires':
								cookieOptions.expires = new Date(val);
								break;
							case 'secure':
								cookieOptions.secure = true;
								break;
							case 'httponly':
								cookieOptions.httpOnly = true;
								break;
							case 'samesite':
								cookieOptions.sameSite = val as 'strict' | 'lax' | 'none';
								break;
						}
					}

					// Ensure path is set (required by SvelteKit)
					if (!cookieOptions.path) {
						cookieOptions.path = '/';
					}

					// Set the cookie on the browser via SvelteKit
					console.log(
						`[${new Date().toISOString()}] handleFetch: Setting cookie "${name}" with options:`,
						cookieOptions
					);
					event.cookies.set(name, value, cookieOptions);
				}
			}
		}

		return response;
	};
}

// Export at the top level
export { handle, handleFetch };
