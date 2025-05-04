import type { ScribeChatSession } from '$lib/types.js';

export async function load({ data, fetch }) {
	const { user } = data;
	let chats: ScribeChatSession[] = []; // Initialize as empty array
	let chatsError = false; // Flag to indicate fetch failure
	if (user) {
		try {
			console.log(`[${new Date().toISOString()}] (chat)/+layout.ts: Fetching /api/chats`);
			const response = await fetch('/api/chats');

			if (response.ok) {
				console.log(`[${new Date().toISOString()}] (chat)/+layout.ts: /api/chats response OK (${response.status})`);
				chats = await response.json();
			} else {
				// Log non-OK responses (like 401)
				console.error(`[${new Date().toISOString()}] (chat)/+layout.ts: Received non-OK status (${response.status}) from /api/chats`);
				chatsError = true; // Set flag on non-OK response
				// Optionally, you could try reading response.text() for more details
				// chats remains an empty array, preventing a crash
			}
		} catch (error: unknown) {
			// Catch network errors or JSON parsing errors
			console.error(`[${new Date().toISOString()}] (chat)/+layout.ts: Error fetching /api/chats:`, error instanceof Error ? error.message : error);
			chatsError = true; // Set flag on fetch/parse error
			// chats remains an empty array
		}
	}
	return {
		// Return the promise for streaming or the resolved array
		// Returning the array directly is simpler if streaming isn't strictly needed here
		chats,
		chatsError, // Return the flag
		...data
	};
}
