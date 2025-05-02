import { writable } from 'svelte/store';
import { v4 as uuidv4 } from 'uuid'; // For generating unique message IDs
import * as apiClient from '$lib/services/apiClient'; // Import API client functions

// Define the structure for a single message
export interface Message {
	id: string;
	sender: 'user' | 'ai';
	content: string;
	isStreaming?: boolean;
	timestamp: Date; // Added for potential future sorting/display
}

// Define the structure for the chat store's state
interface ChatStoreState {
	messages: Message[];
	isLoading: boolean;
	currentSessionId: string | null;
	error: string | null; // Added for potential future error handling
}

// Initialize the store with default values
const initialState: ChatStoreState = {
	messages: [],
	isLoading: false,
	currentSessionId: null,
	error: null,
};

// Create the writable store
const internalChatStore = writable<ChatStoreState>(initialState);
const { subscribe, update, set } = internalChatStore; // Expose core methods

// --- Store Interaction Functions ---

// Helper function to ensure timestamp is a Date object
function parseTimestamp(timestamp: string | Date | undefined): Date {
	if (timestamp instanceof Date) {
		return timestamp;
	}
	if (typeof timestamp === 'string') {
		const date = new Date(timestamp);
		if (!isNaN(date.getTime())) {
			return date;
		}
	}
	// Fallback to current time if timestamp is invalid or missing
	console.warn('Invalid or missing timestamp received, using current time.');
	return new Date();
}


/**
 * Loads messages for a given session from the backend API.
 * @param sessionId The ID of the chat session to load.
 */
async function loadMessages(sessionId: string) {
	if (!sessionId) {
		console.error('loadMessages called without a sessionId');
		set({ ...initialState, error: 'Cannot load messages without a session ID.' });
		return;
	}

	update((state) => ({
		...state,
		isLoading: true,
		error: null,
		messages: [], // Clear previous messages while loading new session
		currentSessionId: sessionId, // Set current session ID immediately
	}));

	try {
		const fetchedMessages = await apiClient.fetchChatMessages(sessionId);
		// Map fetched messages to ensure they conform to the store's Message interface
		const messages = fetchedMessages.map((msg) => ({
			id: msg.id, // Assume backend provides a stable ID
			sender: msg.sender,
			content: msg.content,
			isStreaming: false, // History messages are never streaming
			// Ensure timestamp is a Date object
			timestamp: parseTimestamp(msg.timestamp),
		}));

		update((state) => ({
			...state,
			messages,
			isLoading: false,
			error: null,
		}));
	} catch (error) {
		console.error('Failed to load messages:', error);
		const errorMessage = error instanceof Error ? error.message : 'Unknown error loading messages';
		update((state) => ({
			...state,
			isLoading: false,
			error: `Failed to load chat history: ${errorMessage}`,
			messages: [], // Clear messages on error
		}));
	}
}

/**
 * Sends a user message to the backend and handles the streaming AI response.
 * @param userMessage The content of the user's message.
 */
async function sendMessage(userMessage: string) {
	if (!userMessage.trim()) return; // Don't send empty messages

	let currentSessionId: string | null = null;
	internalChatStore.subscribe(state => { currentSessionId = state.currentSessionId })(); // Get currentSessionId non-reactively

	if (!currentSessionId) {
		console.error('sendMessage called without a currentSessionId.');
		update(state => ({ ...state, error: 'Cannot send message: No active session.' }));
		return;
	}

	const tempUserMessageId = `user-${uuidv4()}`;
	const newUserMessage: Message = {
		id: tempUserMessageId,
		sender: 'user',
		content: userMessage,
		timestamp: new Date(),
		isStreaming: false,
	};

	const tempAiMessageId = `ai-streaming-${uuidv4()}`;
	const placeholderAiMessage: Message = {
		id: tempAiMessageId,
		sender: 'ai',
		content: '', // Start with empty content
		isStreaming: true,
		timestamp: new Date(), // Timestamp when streaming starts
	};

	// Update store optimistically: add user message, placeholder AI message, set loading
	update((state) => ({
		...state,
		messages: [...state.messages, newUserMessage, placeholderAiMessage],
		isLoading: true,
		error: null, // Clear previous errors
	}));

	try {
		await apiClient.generateChatResponse(
			currentSessionId,
			userMessage,
			// onChunk: Append content to the streaming AI message
			(chunk) => { // Removed unused _backendMessageId
				update((state) => {
					const updatedMessages = state.messages.map((msg) => {
						if (msg.id === tempAiMessageId) {
							return { ...msg, content: msg.content + chunk };
						}
						return msg;
					});
					return { ...state, messages: updatedMessages };
				});
			},
			// onError: Update AI message to show error, set store error, stop loading
			(error) => {
				console.error('Streaming error:', error);
				const errorMessage = error instanceof Error ? error.message : 'Unknown streaming error';
				update((state) => {
					const updatedMessages = state.messages.map((msg) => {
						if (msg.id === tempAiMessageId) {
							return {
								...msg,
								content: `Error generating response: ${errorMessage}`,
								isStreaming: false,
								// Optionally update timestamp to error time? Keep start time for now.
							};
						}
						return msg;
					});
					return {
						...state,
						messages: updatedMessages,
						isLoading: false,
						error: `AI response failed: ${errorMessage}`,
					};
				});
			},
			// onComplete: Mark AI message as not streaming, stop loading, update ID if final one provided
			(finalMessageId) => {
				update((state) => {
					const finalMessages = state.messages.map((msg) => {
						if (msg.id === tempAiMessageId) {
							return {
								...msg,
								id: finalMessageId ?? msg.id, // Update ID if backend provided a final one
								isStreaming: false,
								// Optionally update timestamp to completion time? Keep start time for now.
							};
						}
						return msg;
					});
					return {
						...state,
						messages: finalMessages,
						isLoading: false,
						error: null, // Clear error on successful completion
					};
				});
			}
		);
	} catch (error) {
		// Catch errors from the initial fetch call itself (before streaming starts)
		console.error('Failed to initiate message generation:', error);
		const errorMessage = error instanceof Error ? error.message : 'Unknown error sending message';
		update((state) => {
			// Remove the placeholder AI message or mark it as failed immediately
			const updatedMessages = state.messages.filter(msg => msg.id !== tempAiMessageId);
			// Optionally add a generic error message bubble? For now, just set store error.
			return {
				...state,
				messages: updatedMessages, // Remove placeholder on initial fetch error
				isLoading: false,
				error: `Failed to send message: ${errorMessage}`,
			};
		});
	}
}


// --- Export Store and Functions ---

export const chatStore = {
	subscribe, // Essential for Svelte components
	loadMessages,
	sendMessage,
	// Expose set and update primarily for testing or complex scenarios.
	// Components should prefer using loadMessages and sendMessage.
	set,
	update,
};

// Optional: Export types for use in components
export type { ChatStoreState };