import { writable, get } from 'svelte/store'; // Import get
import { generateChatResponse } from '../services/apiClient'; // Import API client function
import { authStore } from './authStore'; // Import authStore to get user ID

// Interface matching backend structure (adjust if needed based on actual API response)
export interface ChatMessage {
	id: string;
	session_id: string;
	user_id: string | null; // AI messages might have null user_id
	sender: 'user' | 'ai';
	content: string;
	created_at: string; // ISO 8601 date string
	updated_at: string; // ISO 8601 date string
    // Optional fields for UI state
    isStreaming?: boolean;
    error?: string;
}

interface ChatStore {
	sessionId: string | null;
	messages: ChatMessage[];
	isLoadingHistory: boolean;
	isGeneratingResponse: boolean;
	error: string | null;
}

const initialState: ChatStore = {
	sessionId: null,
	messages: [],
	isLoadingHistory: false,
	isGeneratingResponse: false,
	error: null
};

function createChatStore() {
	const { subscribe, set, update } = writable<ChatStore>(initialState);

	return {
		subscribe,
		setSessionId: (id: string) => update((state) => ({ ...state, sessionId: id })),
		loadMessages: (messages: ChatMessage[]) =>
			update((state) => ({ ...state, messages, isLoadingHistory: false, error: null })),
		addMessage: (message: ChatMessage) =>
			update((state) => ({ ...state, messages: [...state.messages, message] })),
        updateStreamingMessage: (messageId: string, chunk: string) =>
            update((state) => {
                const messages = state.messages.map((msg) => {
                    if (msg.id === messageId && msg.sender === 'ai') {
                        return { ...msg, content: msg.content + chunk, isStreaming: true };
                    }
                    return msg;
                });
                return { ...state, messages };
            }),
        finalizeStreamingMessage: (messageId: string, error?: string) =>
            update((state) => {
                const messages = state.messages.map((msg) => {
                    if (msg.id === messageId && msg.sender === 'ai') {
                        return { ...msg, isStreaming: false, error: error };
                    }
                    return msg;
                });
                return { ...state, messages, isGeneratingResponse: false }; // Also reset generating state here
            }),
		setLoadingHistory: (loading: boolean) =>
			update((state) => ({ ...state, isLoadingHistory: loading })),
		setGeneratingResponse: (generating: boolean) =>
			update((state) => ({ ...state, isGeneratingResponse: generating })),
		setError: (error: string | null) => update((state) => ({ ...state, error })),
		reset: () => set(initialState),

		// New function to handle sending messages and receiving streamed responses
		sendMessage: async (content: string) => {
			const state = get(chatStore); // Get current store state
			const user = get(authStore).user; // Get current user from authStore

			if (!state.sessionId) {
				console.error('Cannot send message, session ID is not set.');
				update((s) => ({ ...s, error: 'Session ID missing. Cannot send message.' }));
				return;
			}
			if (!user) {
				console.error('Cannot send message, user is not logged in.');
				update((s) => ({ ...s, error: 'User not logged in. Cannot send message.' }));
				return;
			}
			if (state.isGeneratingResponse) {
				console.warn('Already generating response, ignoring new message.');
				return; // Prevent sending multiple messages while waiting
			}

			const userMessageId = crypto.randomUUID(); // Temporary ID for user message
			const aiMessageId = crypto.randomUUID(); // Temporary ID for AI response

			// 1. Add user message immediately to UI
			const userMessage: ChatMessage = {
				id: userMessageId,
				session_id: state.sessionId,
				user_id: user.id, // Use logged-in user's ID
				sender: 'user',
				content: content,
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
			};
			update((s) => ({
				...s,
				messages: [...s.messages, userMessage],
				isGeneratingResponse: true, // Set loading state
				error: null // Clear previous errors
			}));

			// 2. Add AI placeholder message
			const aiPlaceholderMessage: ChatMessage = {
				id: aiMessageId,
				session_id: state.sessionId,
				user_id: null, // AI message has no user_id
				sender: 'ai',
				content: '', // Start empty
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
				isStreaming: true,
			};
		          update((s) => ({ ...s, messages: [...s.messages, aiPlaceholderMessage] }));


			// 3. Call API and handle stream
			try {
				await generateChatResponse(
					state.sessionId,
					content,
					// onChunk callback
					(chunk, messageIdFromServer) => {
		                      // Use the ID from the server if provided, otherwise stick to our generated one
		                      const targetMessageId = messageIdFromServer || aiMessageId;
						update((s) => {
							const messages = s.messages.map((msg) => {
								if (msg.id === targetMessageId && msg.sender === 'ai') {
									// Ensure content is initialized if somehow null/undefined
									const currentContent = msg.content || '';
									return { ...msg, content: currentContent + chunk, isStreaming: true };
								}
								return msg;
							});
							return { ...s, messages };
						});
					},
					// onError callback
					(error) => {
						console.error('Streaming error:', error);
		                      update((s) => {
		                          const messages = s.messages.map((msg) => {
		                              if (msg.id === aiMessageId && msg.sender === 'ai') {
		                                  return { ...msg, isStreaming: false, error: error.message };
		                              }
		                              return msg;
		                          });
		                          // Also set top-level error and stop loading indicator
		                          return { ...s, messages, isGeneratingResponse: false, error: `AI response error: ${error.message}` };
		                      });
					},
					// onComplete callback
					(messageIdFromServer) => {
		                      const finalMessageId = messageIdFromServer || aiMessageId;
						update((s) => {
		                          const messages = s.messages.map((msg) => {
		                              if (msg.id === finalMessageId && msg.sender === 'ai') {
		                                  return { ...msg, isStreaming: false, error: undefined }; // Clear error on success
		                              }
		                              return msg;
		                          });
		                          return { ...s, messages, isGeneratingResponse: false }; // Stop loading indicator
		                      });
					}
				);
			} catch (error) {
				console.error('Failed to send message or initiate stream:', error);
				// Handle errors initiating the request itself
				update((s) => {
		                  const messages = s.messages.map((msg) => {
		                      if (msg.id === aiMessageId && msg.sender === 'ai') {
		                          // Mark the placeholder as errored
		                          return { ...msg, isStreaming: false, error: (error instanceof Error ? error.message : String(error)) };
		                      }
		                      return msg;
		                  });
		                  return {
		                      ...s,
		                      messages,
		                      isGeneratingResponse: false,
		                      error: `Failed to send message: ${error instanceof Error ? error.message : String(error)}`
		                  };
		              });
			}
		}
	};
}

export const chatStore = createChatStore();