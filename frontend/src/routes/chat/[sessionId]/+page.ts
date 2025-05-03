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

	// Set initial state using store methods
	chatStore.setSessionId(sessionId);
	chatStore.setLoadingHistory(true); // Use setLoadingHistory for loading state
	chatStore.setError(null); // Clear any previous errors

	try {
		// Fetch initial messages
		console.log(`Fetching messages for session: ${sessionId}`);
		const initialMessages = await fetchChatMessages(sessionId);
		console.log(`Fetched ${initialMessages.length} messages.`);
		// Update store with messages and reset loading/error states
		chatStore.loadMessages(initialMessages); // Use loadMessages
		// setLoadingHistory(false) is implicitly handled by loadMessages in the store, but we can be explicit if preferred:
		// chatStore.setLoadingHistory(false);
		// chatStore.setError(null); // Also handled by loadMessages
	} catch (err) {
		console.error('Error fetching initial chat messages:', err);
		const errorMessage = err instanceof Error ? err.message : 'Failed to load chat history';
		// Update store with error state
		chatStore.setError(errorMessage); // Use setError
		chatStore.setLoadingHistory(false); // Ensure loading is set to false on error
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