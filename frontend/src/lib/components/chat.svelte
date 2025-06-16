<script lang="ts">
	// Removed Attachment import
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api'; // Import apiClient
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import ChatHeader from './chat-header.svelte';
	import type { User, ScribeCharacter } from '$lib/types.ts'; // Updated import path & Add ScribeCharacter
	import type { ScribeChatSession, ScribeChatMessage } from '$lib/types'; // Import Scribe types
	import type { UserPersona } from '$lib/types';
	import Messages from './messages.svelte';
	import MultimodalInput from './multimodal-input.svelte';
	import SuggestedActions from './suggested-actions.svelte'; // Import SuggestedActions
	import ChatConfigSidebar from './chat-config-sidebar.svelte';
	// Removed untrack import as we no longer use it
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { env } from '$env/dynamic/public';

	let {
		user,
		chat,
		readonly,
		initialMessages,
		character,
		initialChatInputValue
	}: {
		user: User | undefined;
		chat: ScribeChatSession | undefined;
		initialMessages: ScribeChatMessage[];
		readonly: boolean;
		character: ScribeCharacter | null | undefined;
		initialChatInputValue?: string;
	} = $props();

	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const settingsStore = SettingsStore.fromContext();

	// State variables - use props directly for reactivity
	// Note: In Svelte 5, props are already reactive, so we can use them directly

	const chatHistory = ChatHistory.fromContext();

	// Clear selected character and persona when we have a chat
	$effect(() => {
		if (chat?.id) {
			selectedCharacterStore.clear();
			selectedPersonaStore.clear();
		}
	});

	// Scribe chat state management
	let messages = $state<ScribeChatMessage[]>([]); // Start with a truly empty array
	let initialMessagesSet = $state(false); // Flag to ensure we only set initial messages once

	// Message variants storage: messageId -> array of variant contents
	let messageVariants = $state<Map<string, { content: string; timestamp: string }[]>>(new Map());
	let currentVariantIndex = $state<Map<string, number>>(new Map());

	$effect(() => {
		if (!initialMessagesSet) {
			let newInitialMessages: ScribeChatMessage[];
			if (initialMessages.length === 0 && character?.first_mes) {
				const firstMessageId = `first-message-${chat?.id ?? 'initial'}`;
				newInitialMessages = [
					{
						id: firstMessageId,
						session_id: chat?.id ?? 'unknown-session',
						message_type: 'Assistant',
						content: character.first_mes,
						created_at: chat?.created_at ?? new Date().toISOString(),
						user_id: '',
						loading: false
					}
				];
			} else {
				// Ensure any existing initial messages don't have loading=true
				newInitialMessages = initialMessages.map((msg) => ({
					...msg,
					loading: false
				}));
			}
			messages = newInitialMessages;
			initialMessagesSet = true;
		}
	});

	let isLoading = $state(false);
	let error = $state<string | null>(null); // Add error state

	// Removed attachments state as feature is disabled/not supported
	let chatInput = $state(initialChatInputValue || ''); // Initialize with prop
	let currentAbortController = $state<AbortController | null>(null); // For cancelling stream

	// --- Suggested Actions State ---
	let dynamicSuggestedActions = $state<Array<{ action: string }>>([]);
	let isLoadingSuggestions = $state(false);

	// --- Impersonate Response State ---
	// Removed - impersonate now directly sets input text

	// --- Chat Config Sidebar State ---
	let isChatConfigOpen = $state(false);
	let availablePersonas = $state<UserPersona[]>([]);

	// --- State for chat interface visibility ---
	// The entire chat interface (input box, suggestions) should only show when we have both chat AND character
	let shouldShowChatInterface = $state(false);

	// Update visibility when props change
	$effect(() => {
		const hasChat = chat !== undefined && chat !== null;
		const hasCharacter = character !== undefined && character !== null;
		const shouldShow = hasChat && hasCharacter;

		// Debug logging for tests
		if (process.env.NODE_ENV === 'test') {
			console.log('shouldShowChatInterface effect update:', {
				hasChat,
				hasCharacter,
				shouldShow,
				chat_id: chat?.id || 'undefined',
				character_id: character?.id || 'undefined'
			});
		}

		shouldShowChatInterface = shouldShow;
	});

	// Button is enabled when we can actually fetch suggestions (same as interface visibility)
	let canFetchSuggestions = $derived(() => {
		return shouldShowChatInterface;
	});

	// Chat interface state logging removed for production

	// --- Load Available Personas ---
	let lastPersonasLoad = 0;
	const PERSONAS_THROTTLE = 5000; // 5 seconds minimum between loads

	async function loadAvailablePersonas() {
		const now = Date.now();
		if (now - lastPersonasLoad < PERSONAS_THROTTLE) {
			console.log('Throttling personas load request');
			return;
		}

		lastPersonasLoad = now;
		try {
			const result = await apiClient.getUserPersonas();
			if (result.isOk()) {
				availablePersonas = result.value;
				console.log('Loaded personas:', availablePersonas.length);
			} else {
				console.error('Failed to load personas:', result.error);
				// Don't show error for rate limiting
				if ('statusCode' in result.error && result.error.statusCode !== 429) {
					toast.error(`Failed to load personas: ${result.error.message}`);
				} else if (!('statusCode' in result.error)) {
					// Show error for non-response errors (client/network errors)
					toast.error(`Failed to load personas: ${result.error.message}`);
				}
			}
		} catch (error) {
			console.error('Failed to load personas:', error);
			toast.error('Failed to load personas');
		}
	}

	// --- Get Current Chat Model ---
	async function getCurrentChatModel() {
		if (!chat?.id) return null;

		try {
			const result = await apiClient.getChatSessionSettings(chat.id);
			if (result.isOk()) {
				return result.value.model_name || null;
			} else {
				console.error('Failed to get chat model:', result.error);
			}
		} catch (error) {
			console.error('Failed to get chat model:', error);
		}
		return null;
	}

	// Load personas when component mounts (regardless of chat)
	$effect(() => {
		loadAvailablePersonas();
	});

	// --- Scribe Backend Interaction Logic ---

	async function fetchSuggestedActions() {
		console.log('fetchSuggestedActions: Entered function.');

		if (!chat?.id) {
			// Check only for chat.id as per new endpoint
			console.log('fetchSuggestedActions: Aborting, missing chat.id.');
			return;
		}

		console.log('Fetching suggested actions for chat:', chat.id);

		try {
			isLoadingSuggestions = true;
			const result = await apiClient.fetchSuggestedActions(chat.id);

			if (result.isOk()) {
				const responseData = result.value; // This is { suggestions: [...] }
				if (responseData.suggestions && responseData.suggestions.length > 0) {
					dynamicSuggestedActions = responseData.suggestions;
					console.log('Successfully fetched suggested actions:', dynamicSuggestedActions);
				} else {
					console.log('No suggestions returned or suggestions array is empty.');
					dynamicSuggestedActions = [];
				}
			} else {
				const error = result.error;
				console.error('Error fetching suggested actions:', error.message);
				toast.error(`Could not load suggested actions: ${error.message}`);
				dynamicSuggestedActions = [];
			}
		} catch (err: any) {
			// Catch any unexpected errors during the API client call itself
			console.error('Error fetching suggested actions:', err);
			toast.error(`Could not load suggested actions: ${err.message}`);
			dynamicSuggestedActions = [];
		} finally {
			isLoadingSuggestions = false;
		}
	}

	async function sendMessage(content: string) {
		dynamicSuggestedActions = []; // Clear suggestions when a message (including a suggestion) is sent

		// Use user.user_id instead of user.id
		if (!chat?.id || !user?.id) {
			error = 'Chat session or user information is missing.';
			toast.error(error);
			return;
		}

		isLoading = true;
		error = null; // Reset error state at the beginning

		// Add user message optimistically
		const userMessage: ScribeChatMessage = {
			id: crypto.randomUUID(),
			session_id: chat.id,
			message_type: 'User',
			content: content,
			created_at: new Date().toISOString(),
			user_id: user.id, // Use user.id
			loading: false
		};
		messages = [...messages, userMessage];

		// --- Determine history to send ---
		// Check if this is the first user message *before* adding the optimistic message
		const isFirstUserMessage = messages.filter((m) => m.message_type === 'User').length === 0;

		// Map existing messages (excluding loading placeholders) to the API format
		// Assuming backend expects { role: 'user' | 'assistant', content: string }
		const existingHistoryForApi = messages
			.filter((m) => !m.loading && (m.message_type === 'User' || m.message_type === 'Assistant'))
			.map((m) => ({
				role: m.message_type === 'Assistant' ? 'assistant' : 'user',
				content: m.content
			}));

		// Create the new user message object for the API history
		const userMessageForApi = { role: 'user', content: content };

		// Construct the final history to send
		// The existingHistoryForApi already includes the character's first_mes if it was added by the $effect
		const historyToSend = [...existingHistoryForApi, userMessageForApi];

		// --- SSE Handling using Fetch API ---
		currentAbortController = new AbortController();
		const signal = currentAbortController.signal;

		// Add placeholder for assistant message
		const assistantMessageId = crypto.randomUUID();
		console.log('Created assistant message with ID:', assistantMessageId);
		console.log(
			'Current messages before adding assistant message:',
			messages.map((m) => ({ id: m.id, loading: m.loading }))
		);

		let assistantMessage: ScribeChatMessage = {
			id: assistantMessageId,
			session_id: chat.id,
			message_type: 'Assistant',
			content: '', // Start empty, fill with stream
			created_at: new Date().toISOString(), // Placeholder, backend might send final
			user_id: '', // Assistant messages don't have a user_id in the same way
			loading: true
		};
		messages = [...messages, assistantMessage];

		console.log(
			'Current messages after adding assistant message:',
			messages.map((m) => ({ id: m.id, loading: m.loading }))
		);

		let fetchError: any = null; // Variable to store error from fetch/parsing

		try {
			// Use the same environment variable logic as apiClient
			const baseUrl = (env.PUBLIC_API_URL || '').trim();
			const apiUrl = `${baseUrl}/api/chat/${chat.id}/generate`;

			console.log('[sendMessage] Environment check:', {
				'env.PUBLIC_API_URL': env.PUBLIC_API_URL,
				baseUrl: baseUrl,
				apiUrl: apiUrl
			});

			const response = await fetch(apiUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream' // Indicate we want SSE
				},
				credentials: 'include', // Include cookies for authentication
				// Send the constructed history. The backend expects a 'history' field (Vec<ApiChatMessage>)
				// and an optional 'model' field.
				body: JSON.stringify({
					history: historyToSend,
					model: await getCurrentChatModel()
				}), // Include current model selection
				signal: signal // Pass the abort signal
			});

			if (!response.ok) {
				// Check for auth error
				if (response.status === 401) {
					// Emit auth invalidation event
					window.dispatchEvent(new CustomEvent('auth:session-expired'));
					throw new Error('Session expired. Please sign in again.');
				}

				const errorData = await response.json().catch(() => {
					// If we can't parse the error response, provide a better message based on status
					if (response.status >= 500) {
						return {
							message:
								'Server error - the backend may be temporarily unavailable. Please try again.'
						};
					}
					return { message: 'Failed to generate response' };
				});
				throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
			}

			if (!response.body) {
				throw new Error('Response body is null');
			}

			// Process the stream
			const reader = response.body.getReader();
			const decoder = new TextDecoder();
			let buffer = '';
			let currentEvent = 'message'; // Default SSE event type
			let currentData = '';

			while (true) {
				const { value, done } = await reader.read();
				if (done) {
					break; // Exit loop when stream is done
				}
				buffer += decoder.decode(value, { stream: true });

				// Process buffer line by line for SSE messages
				// An SSE message block ends with double newline (\n\n)
				let eventEndIndex;
				while ((eventEndIndex = buffer.indexOf('\n\n')) !== -1) {
					const messageBlock = buffer.substring(0, eventEndIndex);
					buffer = buffer.substring(eventEndIndex + 2); // Consume block + \n\n

					// Reset for each block
					currentEvent = 'message'; // Default if no event line
					currentData = '';

					for (const line of messageBlock.split('\n')) {
						if (line.startsWith('event:')) {
							currentEvent = line.substring(6).trim();
						} else if (line.startsWith('data:')) {
							const dataLineContent = line.substring(5); // Remove "data:" prefix
							// If currentData is not empty, it means this is a subsequent data line for the same event.
							// Prepend a newline. SSE spec implies data lines are concatenated with a newline.
							// The .trimStart() on the original line.substring(5).trimStart() was too aggressive.
							// We should respect leading spaces if the data content itself has them,
							// but the SSE spec says "If the field value is empty, dispatch the event."
							// and "Otherwise, append the field value to a buffer for the field name,
							// then append a single U+000A LINE FEED (LF) character to the buffer."
							// This implies the data from `data: ` lines are effectively newline-separated.
							if (currentData.length > 0) {
								currentData += '\n';
							}
							currentData += dataLineContent.startsWith(' ')
								? dataLineContent.substring(1)
								: dataLineContent;
						} else if (line.startsWith('id:')) {
							// Optional: handle message ID if backend sends it
							// console.log('SSE Message ID:', line.substring(3).trim());
						}
						// Ignore empty lines or lines that are not event, data, or id.
					}
					// currentData is now the complete data for the event.

					// Process the completed event data based on event type
					if (currentEvent === 'done' && currentData === '[DONE]') {
						console.log('SSE stream finished with [DONE] signal.');
						// Finalization happens after the loop
					} else if (currentEvent === 'error') {
						console.error('SSE Error Event:', currentData);
						error = `Stream error: ${currentData}`;
						toast.error(error);
						reader.cancel('SSE error event received');
						throw new Error(error); // Stop processing
					} else if (currentEvent === 'content') {
						if (currentData) {
							messages = messages.map((msg) => {
								if (msg.id === assistantMessageId) {
									console.log(
										'Updating content for assistant message:',
										msg.id,
										'current loading:',
										msg.loading
									);
									return { ...msg, content: msg.content + currentData };
								}
								// Ensure first messages never get loading state during streaming
								if (msg.id.startsWith('first-message-')) {
									if (msg.loading) {
										console.error('FOUND FIRST MESSAGE WITH LOADING=TRUE, FIXING:', msg.id);
									}
									return { ...msg, loading: false };
								}
								return msg;
							});
						}
					} else if (currentEvent === 'reasoning_chunk') {
						if (currentData) {
							console.log('SSE Reasoning Chunk:', currentData);
							// TODO: Decide how to display reasoning chunks if needed.
							// For now, we can append it to a separate field or log it.
							// Example:
							// messages = messages.map(msg =>
							// 	msg.id === assistantMessageId
							// 		? { ...msg, reasoning: (msg.reasoning || '') + currentData }
							// 		: msg
							// );
						}
					} else if (currentEvent === 'message' && currentData) {
						// This is the default event if no 'event:' line is present.
						// The backend now explicitly names events, so this might be less common,
						// but good to handle as a fallback for simple text content.
						console.warn('Received SSE data with default "message" event:', currentData);
						// Try to parse JSON if the data looks like JSON
						let messageContent = currentData;
						try {
							if (currentData.trim() === '[DONE]') {
								// This is a control message, not content
								console.log('SSE stream finished with [DONE] signal.');
								continue; // Skip updating message content for [DONE]
							} else if (currentData.trim().startsWith('{')) {
								const parsedData = JSON.parse(currentData);
								if (parsedData.text) {
									messageContent = parsedData.text;
								}
							}
						} catch (e) {
							console.error('Failed to parse SSE message data as JSON:', e);
							// Continue with the original data on parse error
						}

						// Assuming it's content if not otherwise specified by a known event
						messages = messages.map((msg) =>
							msg.id === assistantMessageId
								? { ...msg, content: msg.content + messageContent }
								: msg
						);
					}
					// else: ignore unknown events or empty data for known events
				}
			}

			// Handle any remaining data in the buffer after the loop (should be empty if stream ended cleanly)

			// Finalize assistant message state only if no error occurred during fetch/parsing
			messages = messages.map((msg) => {
				if (msg.id === assistantMessageId) {
					return { ...msg, loading: false };
				}
				// Ensure first messages never have loading=true
				if (msg.id.startsWith('first-message-')) {
					return { ...msg, loading: false };
				}
				return msg;
			});
		} catch (err: any) {
			fetchError = err; // Store the error
			if (err.name === 'AbortError') {
				console.log('Fetch aborted by user.');
				toast.info('Generation stopped.');
				// Remove the placeholder assistant message if aborted early
				messages = messages.filter((msg) => msg.id !== assistantMessageId);
			} else {
				// Check if this might be an auth error by validating session
				if (err.message?.includes('Session expired') || err.message?.includes('401')) {
					// Auth error already handled by event emission
					console.log('Auth error during chat generation');
				} else {
					// For other errors, validate session to check if it's an indirect auth issue
					import('$lib/api').then(({ apiClient }) => {
						apiClient.getSession().then((result) => {
							if (result.isErr() || !result.value.user) {
								window.dispatchEvent(new CustomEvent('auth:session-expired'));
							}
						});
					});
				}

				// Error might have been set by the 'error' event handler already
				if (!error) {
					// Only set if not already set by SSE 'error' event
					error = err.message || 'An unexpected error occurred.';
					toast.error(error ?? 'Unknown error'); // Ensure non-null string for toast
				}
				// Remove placeholder assistant message on error
				messages = messages.filter((msg) => msg.id !== assistantMessageId);
				// Optionally remove optimistic user message on error
				// messages = messages.filter(m => m.id !== userMessage.id);
			}
		} finally {
			isLoading = false;
			currentAbortController = null; // Clear the controller

			// Only refetch history if the operation wasn't aborted and didn't end in an error
			let shouldRefetch = true;
			if (fetchError && fetchError.name === 'AbortError') {
				shouldRefetch = false;
			}
			// Check if 'error' state was set (either by catch or SSE event)
			if (error) {
				shouldRefetch = false;
			}
			if (shouldRefetch) {
				// Get the latest messages to find the backend message ID for this assistant message
				try {
					const messagesResult = await apiClient.getMessagesByChatId(chat.id);
					if (messagesResult.isOk()) {
						const backendMessages = messagesResult.value;

						// Find the most recent assistant message that matches our content
						const completedAssistantMessage = messages.find(
							(m) => m.id === assistantMessageId && m.message_type === 'Assistant' && !m.loading
						);

						if (completedAssistantMessage && completedAssistantMessage.content.trim()) {
							// Find matching backend message by content (most recent first)
							const matchingBackendMessage = backendMessages
								.filter((msg: any) => msg.message_type === 'Assistant')
								.sort(
									(a: any, b: any) =>
										new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
								)
								.find((msg: any) => {
									const backendContent =
										msg.parts && msg.parts.length > 0 && msg.parts[0].text ? msg.parts[0].text : '';
									return backendContent.trim() === completedAssistantMessage.content.trim();
								});

							if (matchingBackendMessage) {
								// Update the frontend message with the real backend ID
								messages = messages.map((msg) => {
									if (msg.id === assistantMessageId) {
										return {
											...msg,
											backend_id: matchingBackendMessage.id, // Store backend ID separately
											created_at:
												typeof matchingBackendMessage.created_at === 'string'
													? matchingBackendMessage.created_at
													: matchingBackendMessage.created_at.toISOString(),
											session_id: matchingBackendMessage.session_id || msg.session_id
										};
									}
									return msg;
								});
								console.log(
									'Updated assistant message with backend ID:',
									matchingBackendMessage.id
								);
							}

							// Update chat preview in sidebar without triggering full reload
							const preview = completedAssistantMessage.content.trim().substring(0, 100);
							chatHistory.updateChatPreview(chat.id, preview);
						}
					}
				} catch (err) {
					console.warn('Failed to fetch backend message data after streaming:', err);
				}
			}
		}
	}

	// Generate AI response based on current messages (used for edited messages)
	async function generateAIResponse() {
		if (!chat?.id || !user?.id) {
			error = 'Chat session or user information is missing.';
			toast.error(error);
			return;
		}

		isLoading = true;
		error = null;

		// Build history from current messages
		const historyToSend = messages
			.filter((m) => !m.loading && (m.message_type === 'User' || m.message_type === 'Assistant'))
			.map((m) => ({
				role: m.message_type === 'Assistant' ? 'assistant' : 'user',
				content: m.content
			}));

		// Use the same streaming logic as sendMessage but skip user message creation
		currentAbortController = new AbortController();
		const signal = currentAbortController.signal;

		// Add placeholder for assistant message
		const assistantMessageId = crypto.randomUUID();
		console.log('Created assistant message with ID:', assistantMessageId);

		let assistantMessage: ScribeChatMessage = {
			id: assistantMessageId,
			session_id: chat.id,
			message_type: 'Assistant',
			content: '',
			created_at: new Date().toISOString(),
			user_id: '',
			loading: true
		};
		messages = [...messages, assistantMessage];

		let fetchError: any = null;

		try {
			const baseUrl = (env.PUBLIC_API_URL || '').trim();
			const apiUrl = `${baseUrl}/api/chat/${chat.id}/generate`;

			console.log('[generateAIResponse] Environment check:', {
				'env.PUBLIC_API_URL': env.PUBLIC_API_URL,
				baseUrl: baseUrl,
				apiUrl: apiUrl
			});

			const response = await fetch(apiUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream'
				},
				credentials: 'include',
				body: JSON.stringify({
					history: historyToSend,
					model: await getCurrentChatModel()
				}),
				signal: signal
			});

			console.log('[generateAIResponse] Response status:', response.status, 'ok:', response.ok);

			if (!response.ok) {
				if (response.status === 401) {
					window.dispatchEvent(new CustomEvent('auth:session-expired'));
					throw new Error('Session expired. Please sign in again.');
				}

				const errorData = await response.json().catch(() => {
					if (response.status >= 500) {
						return {
							message:
								'Server error - the backend may be temporarily unavailable. Please try again.'
						};
					}
					return { message: 'Failed to generate response' };
				});
				throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
			}

			if (!response.body) {
				throw new Error('Response body is null');
			}

			// Process the stream (same logic as sendMessage)
			const reader = response.body.getReader();
			const decoder = new TextDecoder();
			let buffer = '';
			let currentEvent = 'message';
			let currentData = '';

			while (true) {
				const { value, done } = await reader.read();
				if (done) {
					break;
				}
				const chunk = decoder.decode(value, { stream: true });
				buffer += chunk;

				let eventEndIndex;
				while ((eventEndIndex = buffer.indexOf('\n\n')) !== -1) {
					const messageBlock = buffer.substring(0, eventEndIndex);
					buffer = buffer.substring(eventEndIndex + 2);

					currentEvent = 'message';
					currentData = '';

					for (const line of messageBlock.split('\n')) {
						if (line.startsWith('event:')) {
							currentEvent = line.substring(6).trim();
						} else if (line.startsWith('data:')) {
							const dataLineContent = line.substring(5);
							if (currentData.length > 0) {
								currentData += '\n';
							}
							currentData += dataLineContent.startsWith(' ')
								? dataLineContent.substring(1)
								: dataLineContent;
						}
					}

					if (currentEvent === 'done' && currentData === '[DONE]') {
						console.log('SSE stream finished with [DONE] signal.');
					} else if (currentEvent === 'error') {
						console.error('SSE Error Event:', currentData);
						error = `Stream error: ${currentData}`;
						toast.error(error);
						reader.cancel('SSE error event received');
						throw new Error(error);
					} else if (currentEvent === 'content') {
						if (currentData) {
							messages = messages.map((msg) => {
								if (msg.id === assistantMessageId) {
									return { ...msg, content: msg.content + currentData };
								}
								if (msg.id.startsWith('first-message-')) {
									return { ...msg, loading: false };
								}
								return msg;
							});
						}
					}
				}
			}

			// Finalize assistant message
			messages = messages.map((msg) => {
				if (msg.id === assistantMessageId) {
					return { ...msg, loading: false };
				}
				if (msg.id.startsWith('first-message-')) {
					return { ...msg, loading: false };
				}
				return msg;
			});
		} catch (err: any) {
			fetchError = err;
			if (err.name === 'AbortError') {
				console.log('Generation aborted by user.');
				toast.info('Generation stopped.');
				messages = messages.filter((msg) => msg.id !== assistantMessageId);
			} else {
				if (!error) {
					error = err.message || 'An unexpected error occurred.';
					toast.error(error ?? 'Unknown error');
				}
				messages = messages.filter((msg) => msg.id !== assistantMessageId);
			}
		} finally {
			isLoading = false;
			currentAbortController = null;

			// Update chat preview and message ID as in sendMessage
			let shouldRefetch = true;
			if (fetchError && fetchError.name === 'AbortError') {
				shouldRefetch = false;
			}
			if (error) {
				shouldRefetch = false;
			}
			if (shouldRefetch) {
				try {
					const messagesResult = await apiClient.getMessagesByChatId(chat.id);
					if (messagesResult.isOk()) {
						const backendMessages = messagesResult.value;

						const completedAssistantMessage = messages.find(
							(m) => m.id === assistantMessageId && m.message_type === 'Assistant' && !m.loading
						);

						if (completedAssistantMessage && completedAssistantMessage.content.trim()) {
							const matchingBackendMessage = backendMessages
								.filter((msg: any) => msg.message_type === 'Assistant')
								.sort(
									(a: any, b: any) =>
										new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
								)
								.find((msg: any) => {
									const backendContent =
										msg.parts && msg.parts.length > 0 && msg.parts[0].text ? msg.parts[0].text : '';
									return backendContent.trim() === completedAssistantMessage.content.trim();
								});

							if (matchingBackendMessage) {
								messages = messages.map((msg) => {
									if (msg.id === assistantMessageId) {
										return {
											...msg,
											backend_id: matchingBackendMessage.id,
											created_at:
												typeof matchingBackendMessage.created_at === 'string'
													? matchingBackendMessage.created_at
													: matchingBackendMessage.created_at.toISOString(),
											session_id: matchingBackendMessage.session_id || msg.session_id
										};
									}
									return msg;
								});
								console.log(
									'Updated generated assistant message with backend ID:',
									matchingBackendMessage.id
								);
							}

							const preview = completedAssistantMessage.content.trim().substring(0, 100);
							chatHistory.updateChatPreview(chat.id, preview);
						}
					}
				} catch (err) {
					console.warn('Failed to fetch backend message data after generation:', err);
				}
			}
		}
	}

	function stopGeneration() {
		if (currentAbortController) {
			currentAbortController.abort();
		} else {
			console.warn('Stop generation called but no active request found.');
		}
		// isLoading will be set to false in the finally block of sendMessage
	}

	// Input submission handler
	function handleInputSubmit(e: Event) {
		e.preventDefault();
		if (chatInput.trim() && !isLoading) {
			sendMessage(chatInput.trim());
			chatInput = ''; // Clear input after sending
			// TODO: Reset textarea height in MultimodalInput (might need refactor there)
		}
	}

	// Regenerate AI response without adding a new user message
	async function regenerateResponse(userMessageContent: string, originalMessageId?: string) {
		if (!chat?.id || !user?.id) {
			error = 'Chat session or user information is missing.';
			toast.error(error);
			return;
		}

		isLoading = true;
		error = null;

		// Build the history - messages array already has the right messages after we removed the assistant message
		// Just convert to API format
		const historyToSend = messages
			.filter((m) => !m.loading && (m.message_type === 'User' || m.message_type === 'Assistant'))
			.map((m) => ({
				role: m.message_type === 'Assistant' ? 'assistant' : 'user',
				content: m.content
			}));

		// Continue with the same streaming logic as sendMessage but skip user message creation
		currentAbortController = new AbortController();
		const signal = currentAbortController.signal;

		// Use the original message ID if provided (for variants), otherwise create a new one
		const assistantMessageId = originalMessageId || crypto.randomUUID();
		console.log('Using assistant message ID:', assistantMessageId, 'Original:', originalMessageId);

		let assistantMessage: ScribeChatMessage = {
			id: assistantMessageId,
			session_id: chat.id,
			message_type: 'Assistant',
			content: '',
			created_at: new Date().toISOString(),
			user_id: '',
			loading: true
		};
		messages = [...messages, assistantMessage];

		let fetchError: any = null;

		try {
			const baseUrl = (env.PUBLIC_API_URL || '').trim();
			const apiUrl = `${baseUrl}/api/chat/${chat.id}/generate`;

			console.log('[regenerateResponse] Environment check:', {
				'env.PUBLIC_API_URL': env.PUBLIC_API_URL,
				baseUrl: baseUrl,
				apiUrl: apiUrl
			});

			const response = await fetch(apiUrl, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream'
				},
				credentials: 'include',
				body: JSON.stringify({
					history: historyToSend,
					model: await getCurrentChatModel()
				}),
				signal: signal
			});

			console.log('[regenerateResponse] Response status:', response.status, 'ok:', response.ok);
			console.log('[regenerateResponse] Response headers:', response.headers);

			if (!response.ok) {
				if (response.status === 401) {
					window.dispatchEvent(new CustomEvent('auth:session-expired'));
					throw new Error('Session expired. Please sign in again.');
				}

				const errorData = await response.json().catch(() => {
					if (response.status >= 500) {
						return {
							message:
								'Server error - the backend may be temporarily unavailable. Please try again.'
						};
					}
					return { message: 'Failed to generate response' };
				});
				throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
			}

			if (!response.body) {
				throw new Error('Response body is null');
			}

			console.log('[regenerateResponse] Response body exists, starting to read stream');

			// Process the stream (same logic as sendMessage)
			const reader = response.body.getReader();
			const decoder = new TextDecoder();
			let buffer = '';
			let currentEvent = 'message';
			let currentData = '';

			while (true) {
				const { value, done } = await reader.read();
				if (done) {
					console.log('[regenerateResponse] Stream reading done');
					break;
				}
				const chunk = decoder.decode(value, { stream: true });
				console.log('[regenerateResponse] Received chunk:', chunk);
				buffer += chunk;

				let eventEndIndex;
				while ((eventEndIndex = buffer.indexOf('\n\n')) !== -1) {
					const messageBlock = buffer.substring(0, eventEndIndex);
					buffer = buffer.substring(eventEndIndex + 2);

					currentEvent = 'message';
					currentData = '';

					for (const line of messageBlock.split('\n')) {
						if (line.startsWith('event:')) {
							currentEvent = line.substring(6).trim();
						} else if (line.startsWith('data:')) {
							const dataLineContent = line.substring(5);
							if (currentData.length > 0) {
								currentData += '\n';
							}
							currentData += dataLineContent.startsWith(' ')
								? dataLineContent.substring(1)
								: dataLineContent;
						}
					}

					console.log('[regenerateResponse] Processing event:', currentEvent, 'data:', currentData);

					if (currentEvent === 'done' && currentData === '[DONE]') {
						console.log('SSE stream finished with [DONE] signal.');
					} else if (currentEvent === 'error') {
						console.error('SSE Error Event:', currentData);
						error = `Stream error: ${currentData}`;
						toast.error(error);
						reader.cancel('SSE error event received');
						throw new Error(error);
					} else if (currentEvent === 'content') {
						if (currentData) {
							messages = messages.map((msg) => {
								if (msg.id === assistantMessageId) {
									console.log(
										'[regenerateResponse] Updating message content for:',
										assistantMessageId
									);
									return { ...msg, content: msg.content + currentData };
								}
								if (msg.id.startsWith('first-message-')) {
									return { ...msg, loading: false };
								}
								return msg;
							});
						}
					} else if (currentEvent === 'reasoning_chunk') {
						// Handle reasoning chunks like in sendMessage
						if (currentData) {
							console.log('SSE Reasoning Chunk:', currentData);
						}
					}
				}
			}

			// Finalize assistant message
			messages = messages.map((msg) => {
				if (msg.id === assistantMessageId) {
					return { ...msg, loading: false };
				}
				if (msg.id.startsWith('first-message-')) {
					return { ...msg, loading: false };
				}
				return msg;
			});
		} catch (err: any) {
			fetchError = err;
			if (err.name === 'AbortError') {
				console.log('Regeneration aborted by user.');
				toast.info('Generation stopped.');
				messages = messages.filter((msg) => msg.id !== assistantMessageId);
			} else {
				if (!error) {
					error = err.message || 'An unexpected error occurred.';
					toast.error(error ?? 'Unknown error');
				}
				messages = messages.filter((msg) => msg.id !== assistantMessageId);
			}
		} finally {
			isLoading = false;
			currentAbortController = null;

			// Update chat preview and message ID as in sendMessage
			let shouldRefetch = true;
			if (fetchError && fetchError.name === 'AbortError') {
				shouldRefetch = false;
			}
			if (error) {
				shouldRefetch = false;
			}
			if (shouldRefetch) {
				try {
					const messagesResult = await apiClient.getMessagesByChatId(chat.id);
					if (messagesResult.isOk()) {
						const backendMessages = messagesResult.value;

						const completedAssistantMessage = messages.find(
							(m) => m.id === assistantMessageId && m.message_type === 'Assistant' && !m.loading
						);

						if (completedAssistantMessage && completedAssistantMessage.content.trim()) {
							const matchingBackendMessage = backendMessages
								.filter((msg: any) => msg.message_type === 'Assistant')
								.sort(
									(a: any, b: any) =>
										new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
								)
								.find((msg: any) => {
									const backendContent =
										msg.parts && msg.parts.length > 0 && msg.parts[0].text ? msg.parts[0].text : '';
									return backendContent.trim() === completedAssistantMessage.content.trim();
								});

							if (matchingBackendMessage) {
								messages = messages.map((msg) => {
									if (msg.id === assistantMessageId) {
										return {
											...msg,
											backend_id: matchingBackendMessage.id, // Store backend ID separately
											created_at:
												typeof matchingBackendMessage.created_at === 'string'
													? matchingBackendMessage.created_at
													: matchingBackendMessage.created_at.toISOString(),
											session_id: matchingBackendMessage.session_id || msg.session_id
										};
									}
									return msg;
								});
								console.log(
									'Updated regenerated assistant message with backend ID:',
									matchingBackendMessage.id
								);
							}

							// If this was a regeneration (variant), save the new content
							if (originalMessageId && completedAssistantMessage) {
								const variants = messageVariants.get(originalMessageId) || [];

								// Save the new variant
								variants.push({
									content: completedAssistantMessage.content,
									timestamp: completedAssistantMessage.created_at || new Date().toISOString()
								});
								messageVariants.set(originalMessageId, variants);

								// Now update the current index to point to the newly created variant
								currentVariantIndex.set(originalMessageId, variants.length - 1);
							}

							const preview = completedAssistantMessage.content.trim().substring(0, 100);
							chatHistory.updateChatPreview(chat.id, preview);
						}
					}
				} catch (err) {
					console.warn('Failed to fetch backend message data after regeneration:', err);
				}
			}
		}
	}

	// Handle greeting changes from alternate greetings
	function handleGreetingChanged(event: CustomEvent) {
		const { content } = event.detail;

		// Update the first message content in the messages array
		const firstMessageId = `first-message-${chat?.id ?? 'initial'}`;
		messages = messages.map((msg) => (msg.id === firstMessageId ? { ...msg, content } : msg));
	}

	// Message action handlers
	async function handleRetryMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Retry message:', messageId);

		// Find the assistant message to retry
		const messageIndex = messages.findIndex((msg) => msg.id === messageId);
		if (messageIndex === -1) return;

		const targetMessage = messages[messageIndex];
		if (targetMessage.message_type !== 'Assistant') return;

		// Initialize variants array if this is the first retry
		let variants = messageVariants.get(messageId) || [];

		// If this is the first retry (no variants exist), save the original message as index 0
		if (variants.length === 0 && targetMessage.content.trim()) {
			variants.push({
				content: targetMessage.content,
				timestamp: targetMessage.created_at || new Date().toISOString()
			});
			messageVariants.set(messageId, variants);
		}

		// Don't update the current index yet - wait until the new variant is actually generated
		// This keeps the UI showing the current count (e.g., 2/2) until the new one exists

		// Find the previous user message to regenerate from
		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = messages[userMessageIndex];
		if (userMessage.message_type !== 'User') return;

		// Remove the assistant message and any messages after it
		const removedMessages = messages.slice(messageIndex);
		messages = messages.slice(0, messageIndex);

		// Clean up variant data for any messages that will be removed (except the one we're regenerating)
		for (const removedMsg of removedMessages) {
			if (removedMsg.id !== messageId) {
				messageVariants.delete(removedMsg.id);
				currentVariantIndex.delete(removedMsg.id);
			}
		}

		// Delete trailing messages from backend (including embeddings)
		// Only delete messages after the one we're regenerating
		const messagesToDelete = removedMessages.filter((msg) => msg.id !== messageId);
		if (messagesToDelete.length > 0 && messagesToDelete[0].backend_id) {
			try {
				await apiClient.deleteTrailingMessages(messagesToDelete[0].backend_id);
			} catch (err) {
				console.warn('Failed to delete trailing messages from backend:', err);
				// Continue with regeneration even if cleanup fails
			}
		}

		// Regenerate the response by calling the streaming logic directly
		// Pass the original messageId so we can maintain variants
		regenerateResponse(userMessage.content, messageId);
	}

	function handleEditMessage(messageId: string) {
		console.log('Edit message:', messageId);
		// TODO: Implement edit logic for assistant messages
		// This is currently only used for assistant messages (user messages use inline editing)
	}

	async function handleSaveEditedMessage(messageId: string, newContent: string) {
		console.log('Save edited message:', messageId, 'New content:', newContent);

		if (!chat?.id || isLoading) return;

		// Find the message index
		const messageIndex = messages.findIndex((msg) => msg.id === messageId);
		if (messageIndex === -1) return;

		const targetMessage = messages[messageIndex];
		if (targetMessage.message_type !== 'User') return;

		// Update the message content
		messages = messages.map((msg) => {
			if (msg.id === messageId) {
				return {
					...msg,
					content: newContent
				};
			}
			return msg;
		});

		// Get messages that will be removed for backend cleanup
		const removedMessages = messages.slice(messageIndex + 1);

		// Clear all subsequent messages (everything after this user message)
		messages = messages.slice(0, messageIndex + 1);

		// Clear any variant data for removed messages
		const keptMessageIds = new Set(messages.map((m) => m.id));
		for (const [variantMessageId] of messageVariants) {
			if (!keptMessageIds.has(variantMessageId)) {
				messageVariants.delete(variantMessageId);
				currentVariantIndex.delete(variantMessageId);
			}
		}

		// Delete trailing messages from backend (including embeddings)
		if (removedMessages.length > 0 && removedMessages[0].backend_id) {
			try {
				await apiClient.deleteTrailingMessages(removedMessages[0].backend_id);
			} catch (err) {
				console.warn('Failed to delete trailing messages from backend:', err);
				// Continue with regeneration even if cleanup fails
			}
		}

		// Generate new AI response based on the edited message
		// Don't use sendMessage since we already have the user message - just trigger AI response
		generateAIResponse();
	}

	function handlePreviousVariant(messageId: string) {
		console.log('Previous variant:', messageId);

		const variants = messageVariants.get(messageId);
		const currentIndex = currentVariantIndex.get(messageId) ?? 0;

		// Can't go back if we're at index 0 (original message)
		if (currentIndex <= 0) return;

		const newIndex = currentIndex - 1;
		currentVariantIndex.set(messageId, newIndex);

		// Update the message content with the previous variant
		if (variants && newIndex < variants.length) {
			messages = messages.map((msg) => {
				if (msg.id === messageId) {
					return {
						...msg,
						content: variants[newIndex].content
					};
				}
				return msg;
			});
		}
	}

	function handleNextVariant(messageId: string) {
		console.log('Next variant / Regenerate:', messageId);

		const variants = messageVariants.get(messageId) || [];
		const currentIndex = currentVariantIndex.get(messageId) ?? 0;

		// If we have saved variants and we're not at the latest one
		if (variants.length > 0 && currentIndex < variants.length - 1) {
			// Show next variant
			const newIndex = currentIndex + 1;
			currentVariantIndex.set(messageId, newIndex);

			messages = messages.map((msg) => {
				if (msg.id === messageId) {
					return {
						...msg,
						content: variants[newIndex].content
					};
				}
				return msg;
			});
		} else {
			// No more variants, generate a new one
			handleRetryMessage(messageId);
		}
	}
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
	<!-- ChatHeader type mismatch fixed by updating ChatHeader component -->
	<ChatHeader {user} {chat} {readonly} />
	<Messages
		{readonly}
		loading={isLoading}
		{messages}
		selectedCharacterId={selectedCharacterStore.characterId}
		{character}
		{user}
		{messageVariants}
		{currentVariantIndex}
		onRetryMessage={handleRetryMessage}
		onEditMessage={handleEditMessage}
		onSaveEditedMessage={handleSaveEditedMessage}
		onPreviousVariant={handlePreviousVariant}
		onNextVariant={handleNextVariant}
		on:personaCreated
		on:greetingChanged={handleGreetingChanged}
	/>

	<!-- Show Chat Interface (Get Suggestions + Input) Only When Inside Active Chat -->
	{#if shouldShowChatInterface}
		<!-- Get Suggestions Button -->
		<div class="mx-auto w-full px-4 pb-1 text-center md:max-w-3xl">
			<button
				type="button"
				onclick={() => {
					// Always log this message for the test to pass, regardless of environment
					console.log('Get Suggestions button clicked!');
					fetchSuggestedActions();
				}}
				disabled={!canFetchSuggestions || isLoadingSuggestions || isLoading}
				class="inline-flex h-10 items-center justify-center gap-2 whitespace-nowrap rounded-md border border-input bg-background px-4 py-2 text-sm font-medium ring-offset-background transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
			>
				{#if isLoadingSuggestions}
					<svg
						class="-ml-1 mr-2 h-4 w-4 animate-spin text-primary"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"
						></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Loading...
				{:else}
					Get Suggestions
				{/if}
			</button>
		</div>

		<!-- Suggested Actions -->
		{#if dynamicSuggestedActions.length > 0 && !isLoading}
			<div class="mx-auto w-full px-4 pb-2 md:max-w-3xl">
				<SuggestedActions
					{user}
					{sendMessage}
					actions={dynamicSuggestedActions}
					onClear={() => {
						dynamicSuggestedActions = [];
					}}
					onEdit={(content) => {
						chatInput = content;
					}}
				/>
			</div>
		{/if}


		<!-- Message Input Form -->
		<div class="mx-auto w-full px-4 pb-4 md:max-w-3xl md:pb-6">
			<form
				onsubmit={(e) => {
					e.preventDefault();
					handleInputSubmit(e);
				}}
			>
				{#if !readonly}
					<MultimodalInput 
						bind:value={chatInput} 
						{isLoading} 
						{stopGeneration} 
						chatId={chat?.id}
						onImpersonate={(response) => {
							chatInput = response;
						}}
					/>
				{/if}
			</form>
		</div>
	{/if}
</div>

<!-- Chat Configuration Sidebar -->
{#if chat}
	<ChatConfigSidebar
		bind:isOpen={isChatConfigOpen}
		{chat}
		{availablePersonas}
		on:settingsUpdated={(event) => {
			console.log('Chat settings updated:', event.detail);
		}}
		on:personaChanged={(event) => {
			console.log('Persona changed:', event.detail);
		}}
	/>
{/if}
