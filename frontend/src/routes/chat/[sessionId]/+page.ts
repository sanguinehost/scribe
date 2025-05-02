import { chatStore } from '$lib/stores/chatStore';
import { fetchChatMessages } from '$lib/services/apiClient';
import type { PageLoad } from './$types'; // Revert to standard SvelteKit type import
import { error } from '@sveltejs/kit';

export const load: PageLoad = async ({ params }) => { // Type inference should work with $types
	const sessionId = params.sessionId;

	if (!sessionId) {
		// Should not happen with the route structure, but good practice
		throw error(400, 'Session ID is required');
	}

	// Update the store using chatStore.update()
	chatStore.update((state) => ({ ...state, currentSessionId: sessionId, isLoading: true, error: null }));

	try {
		// Fetch initial messages
		console.log(`Fetching messages for session: ${sessionId}`);
		const initialMessages = await fetchChatMessages(sessionId);
		console.log(`Fetched ${initialMessages.length} messages.`);
		// Update store with messages and reset loading/error states
		chatStore.update((state) => ({
			...state,
			messages: initialMessages,
			isLoading: false,
			error: null
		}));
	} catch (err) {
		console.error('Error fetching initial chat messages:', err);
		const errorMessage = err instanceof Error ? err.message : 'Failed to load chat history';
		// Update store with error state
		chatStore.update((state) => ({
			...state,
			isLoading: false,
			error: errorMessage
		}));
		// Optionally, re-throw a SvelteKit error to show an error page,
		// or let the component handle the error state from the store.
		// For now, we'll let the component handle it via the store.
		// throw error(500, `Failed to load chat history: ${errorMessage}`);
	}

	// Return the sessionId, although the component primarily relies on the store
	return {
		sessionId
	};
};