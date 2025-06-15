import type { ScribeChatSession } from '$lib/types.js';
import { apiClient } from '$lib/api';

export async function load({ data, fetch }) {
	const { user } = data;
	let chats: ScribeChatSession[] = []; // Initialize as empty array
	let chatsError = false; // Flag to indicate fetch failure
	if (user) {
		try {
			const result = await apiClient.getChats();

			if (result.isOk()) {
				chats = result.value;
			} else {
				// Log API errors
				console.error(
					`[${new Date().toISOString()}] (chat)/+layout.ts: API error fetching chats:`,
					result.error
				);
				chatsError = true; // Set flag on API error
				// chats remains an empty array, preventing a crash
			}
		} catch (error: unknown) {
			// Catch network errors or other unexpected errors
			console.error(
				`[${new Date().toISOString()}] (chat)/+layout.ts: Error fetching chats:`,
				error instanceof Error ? error.message : error
			);
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
