// CRITICAL: Import static env FIRST before any other imports
// This is safe because it's baked at build time
import { PUBLIC_ENVIRONMENT } from '$env/static/public';
import type { Handle, HandleFetch } from '@sveltejs/kit';
import { logger } from '$lib/utils/logger';

logger.debug('hooks-server', 'File loaded', { environment: PUBLIC_ENVIRONMENT });

// Check if we're in desktop mode - this prevents loading server-side modules in browser
const isDesktop = PUBLIC_ENVIRONMENT === 'desktop';
logger.debug('hooks-server', 'Desktop mode check', { isDesktop });

// Declare functions that will be conditionally assigned
let handle: Handle;
let handleFetch: HandleFetch;

// Desktop mode: Use no-op functions that do nothing
// These run entirely in the browser and don't need Node.js runtime
if (isDesktop) {
	handle = async ({ event, resolve }) => {
		logger.debug('hooks-server-desktop', 'Handle called', { url: event.url.toString() });
		// Just pass through - no server-side auth in desktop mode
		return resolve(event);
	};

	handleFetch = async ({ request, fetch }) => {
		logger.debug('hooks-server-desktop', 'HandleFetch called', { url: request.url });
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
		logger.debug('hooks-server-cloud-fetch', 'Processing request', {
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
			logger.debug('hooks-server-cloud-fetch', 'Forwarding cookies to API');

			// Get cookies from the original request
			const cookies = event.request.headers.get('cookie');
			if (cookies) {
				logger.debug('hooks-server-cloud-fetch', 'Adding cookies to request', { cookies });
				request.headers.set('cookie', cookies);
			} else {
				logger.debug('hooks-server-cloud-fetch', 'No cookies found to forward');
			}
		}

		const response = await fetch(request);

		// Log response details
		logger.debug('hooks-server-cloud-fetch', 'Response received', {
			url: request.url,
			status: response.status,
			headers: Object.fromEntries(response.headers.entries()),
			ok: response.ok
		});

		// Forward Set-Cookie headers from API responses to the browser
		if (isProductionAPI || isLocalAPI) {
			const setCookieHeaders = response.headers.getSetCookie?.() || [];
			logger.debug('hooks-server-cloud-fetch', 'Processing Set-Cookie headers', {
				count: setCookieHeaders.length
			});
			logger.debug('hooks-server-cloud-fetch', 'Raw response headers', {
				headers: Object.fromEntries(response.headers.entries())
			});

			for (const cookieHeader of setCookieHeaders) {
				logger.debug('hooks-server-cloud-fetch', 'Raw cookie header', {
					cookieHeader: JSON.stringify(cookieHeader)
				});

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
					logger.debug('hooks-server-cloud-fetch', 'Setting cookie', {
						name,
						options: cookieOptions
					});
					event.cookies.set(name, value, cookieOptions);
				}
			}
		}

		return response;
	};
}

// Export at the top level
export { handle, handleFetch };
