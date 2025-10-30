import type { ScribeChatSession, User } from '$lib/types.js';
import { apiClient as _apiClient } from '$lib/api';
import { SelectedModel } from '$lib/hooks/selected-model.svelte.js';
import { chatModels, DEFAULT_CHAT_MODEL } from '$lib/ai/models';

// Define the parent data type (from root +layout.server.ts in cloud mode)
interface ParentData {
	user?: User;
	sidebarCollapsed?: boolean;
}

export async function load({ data, fetch }: { data: ParentData; fetch: typeof globalThis.fetch }) {
	// In desktop mode with ssr:false, parent data may be undefined
	const user = data?.user ?? undefined;

	// For desktop mode, provide default values for missing server-side data
	// In cloud mode, these would come from +layout.server.ts
	const sidebarCollapsed = data?.sidebarCollapsed ?? false;

	// Select a default chat model (in cloud mode, this comes from cookies)
	const modelId = DEFAULT_CHAT_MODEL;
	if (chatModels.find((model) => model.id === modelId)) {
		// Model exists, use it
	}
	const selectedChatModel = new SelectedModel(modelId);

	let chats: ScribeChatSession[] = []; // Initialize as empty array
	let chatsError = false; // Flag to indicate fetch failure
	if (user) {
		try {
			// Initialize API client with server-side fetch
			_apiClient.setFetch(fetch);
			const result = await _apiClient.getChats();

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
		// Required properties for (chat)/+layout.svelte
		user: user as User | undefined,
		sidebarCollapsed,
		selectedChatModel,
		// In desktop mode, parent data may be undefined, so spread it safely
		...(data ?? {})
	};
}
