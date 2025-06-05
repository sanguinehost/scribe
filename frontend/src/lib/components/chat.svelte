<script lang="ts">
	// Removed Attachment import
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api'; // Import apiClient
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import ChatHeader from './chat-header.svelte';
	import type { User, ScribeCharacter } from '$lib/types'; // Updated import path & Add ScribeCharacter
	import type { ScribeChatSession, ScribeChatMessage } from '$lib/types'; // Import Scribe types
	import type { UserPersona } from '$lib/types';
	import Messages from './messages.svelte';
	import MultimodalInput from './multimodal-input.svelte';
	import SuggestedActions from './suggested-actions.svelte'; // Import SuggestedActions
	import ChatConfigSidebar from './chat-config-sidebar.svelte';
	import { untrack } from 'svelte'; // Remove incorrect effect import
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';

	let {
		user,
		chat,
		readonly,
		initialMessages: initialMessagesProp,
		character: characterProp,
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

	// State variables
	const currentInitialMessages = initialMessagesProp;
	const currentCharacter = characterProp;
	const currentChat = chat; // chat prop is also used in logic

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

	$effect(() => {
		if (!initialMessagesSet) {
			let newInitialMessages: ScribeChatMessage[];
			if (initialMessagesProp.length === 0 && characterProp?.first_mes) {
				const firstMessageId = `first-message-${chat?.id ?? 'initial'}`;
				newInitialMessages = [{
					id: firstMessageId,
					session_id: chat?.id ?? 'unknown-session',
					message_type: 'Assistant',
					content: characterProp.first_mes,
					created_at: chat?.created_at ?? new Date().toISOString(),
					user_id: '',
					loading: false
				}];
			} else {
				newInitialMessages = initialMessagesProp;
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

	// --- Chat Config Sidebar State ---
	let isChatConfigOpen = $state(false);
	let availablePersonas = $state<UserPersona[]>([]);

	// --- Derived state for button disabled logic ---
	// Button is enabled if there's a chat and the character has a first message.
	// The actual context for suggestions will be determined by fetchSuggestedActions.
	let canFetchSuggestions = $derived(() => {
	  return !!(currentChat && currentCharacter?.first_mes);
	});

	$effect(() => {
		// Only run in development, not in test environment
		if (process.env.NODE_ENV !== 'test') {
			console.log('Button disabled check:', {
				canFetchSuggestions: canFetchSuggestions,
				isLoadingSuggestions: isLoadingSuggestions,
				isLoading: isLoading,
				not_canFetchSuggestions: !canFetchSuggestions,
				// Individual parts of canFetchSuggestions for detailed debugging:
				hasCurrentChat: !!currentChat,
				hasCharacterFirstMes: !!currentCharacter?.first_mes,
				hasUserMessage: !!messages.find(m => m.message_type === 'User'),
				hasAiResponseAfterUser: !!messages.find(m =>
					m.message_type === 'Assistant' &&
					m.id !== `first-message-${currentChat?.id ?? 'initial'}` &&
					(messages.find(um => um.message_type === 'User') ? new Date(m.created_at ?? '') > new Date(messages.find(um => um.message_type === 'User')!.created_at ?? '') : false)
				)
			});
		}
	});

	// --- Load Available Personas ---
	async function loadAvailablePersonas() {
		try {
			const response = await fetch('/api/personas');
			if (response.ok) {
				availablePersonas = await response.json();
			}
		} catch (error) {
			console.error('Failed to load personas:', error);
		}
	}

	// Load personas when component mounts
	$effect(() => {
		if (currentChat) {
			loadAvailablePersonas();
		}
	});

	// --- Scribe Backend Interaction Logic ---

	async function fetchSuggestedActions() {
		console.log('fetchSuggestedActions: Entered function.');

		if (!currentChat?.id) { // Check only for currentChat.id as per new endpoint
			console.log('fetchSuggestedActions: Aborting, missing currentChat.id.');
			return;
		}

		console.log('Fetching suggested actions for chat:', currentChat.id);

		try {
			isLoadingSuggestions = true;
			const result = await apiClient.fetchSuggestedActions(currentChat.id);

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
		} catch (err: any) { // Catch any unexpected errors during the API client call itself
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
		if (!currentChat?.id || !user?.id) {
			error = 'Chat session or user information is missing.';
			toast.error(error);
			return;
		}

		isLoading = true;
		error = null; // Reset error state at the beginning

		// Add user message optimistically
		const userMessage: ScribeChatMessage = {
			id: crypto.randomUUID(),
			session_id: currentChat.id,
			message_type: 'User',
			content: content,
			created_at: new Date().toISOString(),
			user_id: user.id, // Use user.id
			loading: false,
		};
		messages = [...messages, userMessage];

		// --- Determine history to send ---
		// Check if this is the first user message *before* adding the optimistic message
		const isFirstUserMessage = messages.filter(m => m.message_type === 'User').length === 0;

		// Map existing messages (excluding loading placeholders) to the API format
		// Assuming backend expects { role: 'user' | 'assistant', content: string }
		const existingHistoryForApi = messages
			.filter(m => !m.loading && (m.message_type === 'User' || m.message_type === 'Assistant'))
			.map(m => ({
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
		let assistantMessage: ScribeChatMessage = {
			id: assistantMessageId,
			session_id: currentChat.id,
			message_type: 'Assistant',
			content: '', // Start empty, fill with stream
			created_at: new Date().toISOString(), // Placeholder, backend might send final
			user_id: '', // Assistant messages don't have a user_id in the same way
			loading: true,
		};
		messages = [...messages, assistantMessage];

		let fetchError: any = null; // Variable to store error from fetch/parsing

		try {
			const response = await fetch(`/api/chat/${currentChat.id}/generate`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Accept': 'text/event-stream' // Indicate we want SSE
				},
				// Send the constructed history. The backend expects a 'history' field (Vec<ApiChatMessage>)
				// and an optional 'model' field.
				body: JSON.stringify({ history: historyToSend }), // Corrected body
				signal: signal, // Pass the abort signal
			});

			if (!response.ok) {
				const errorData = await response.json().catch(() => ({ message: 'Failed to generate response' }));
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
							currentData += dataLineContent.startsWith(' ') ? dataLineContent.substring(1) : dataLineContent;

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
							messages = messages.map(msg =>
								msg.id === assistantMessageId
									? { ...msg, content: msg.content + currentData }
									: msg
							);
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
						messages = messages.map(msg =>
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
			messages = messages.map(msg =>
				msg.id === assistantMessageId ? { ...msg, loading: false } : msg
			);

		} catch (err: any) {
			fetchError = err; // Store the error
			if (err.name === 'AbortError') {
				console.log('Fetch aborted by user.');
				toast.info('Generation stopped.');
				// Remove the placeholder assistant message if aborted early
				messages = messages.filter(msg => msg.id !== assistantMessageId);
			} else {
				// Error might have been set by the 'error' event handler already
				if (!error) { // Only set if not already set by SSE 'error' event
					error = err.message || 'An unexpected error occurred.';
					toast.error(error ?? 'Unknown error'); // Ensure non-null string for toast
				}
				// Remove placeholder assistant message on error
				messages = messages.filter(msg => msg.id !== assistantMessageId);
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
				// Use untrack to prevent refetch from triggering reactivity loops if history affects messages
				untrack(() => chatHistory.refetch());
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

	// Handle greeting changes from alternate greetings
	function handleGreetingChanged(event: CustomEvent) {
		const { index, content } = event.detail;
		
		// Update the first message content in the messages array
		const firstMessageId = `first-message-${chat?.id ?? 'initial'}`;
		messages = messages.map(msg => 
			msg.id === firstMessageId 
				? { ...msg, content }
				: msg
		);
	}
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
	<!-- ChatHeader type mismatch fixed by updating ChatHeader component -->
	<ChatHeader {user} {chat} {readonly} />
	<Messages
		{readonly}
		loading={isLoading}
		messages={messages}
		selectedCharacterId={selectedCharacterStore.characterId}
		character={currentCharacter}
		on:personaCreated
		on:greetingChanged={handleGreetingChanged}
	/>

	<!-- Add Button Here -->
	<div class="mx-auto w-full px-4 pb-1 md:max-w-3xl text-center">
		<button
			type="button"
			onclick={() => {
				// Always log this message for the test to pass, regardless of environment
				console.log('Get Suggestions button clicked!');
				fetchSuggestedActions();
			}}
			disabled={!canFetchSuggestions || isLoadingSuggestions || isLoading}
			class="ring-offset-background focus-visible:ring-ring inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 border-input bg-background hover:bg-accent hover:text-accent-foreground border h-10 px-4 py-2 text-sm"
		>
			{#if isLoadingSuggestions}
				<svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-primary" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
					<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
					<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
				</svg>
				Loading...
			{:else}
				Get Suggestions
			{/if}
		</button>
	</div>

	{#if dynamicSuggestedActions.length > 0 && !isLoading}
		<div class="mx-auto w-full px-4 pb-2 md:max-w-3xl">
			<SuggestedActions {user} {sendMessage} actions={dynamicSuggestedActions} />
		</div>
	{/if}

	<form
		class="mx-auto flex w-full gap-2 bg-background px-4 pb-4 md:max-w-3xl md:pb-6"
		onsubmit={e => { e.preventDefault(); handleInputSubmit(e); }}
	>
		{#if !readonly}
			<MultimodalInput
				{user}
				bind:value={chatInput}
				{isLoading}
				{sendMessage}
				{stopGeneration}
				class="flex-1"
			/>
		{/if}
	</form>
</div>

<!-- Chat Configuration Sidebar -->
{#if currentChat}
	<ChatConfigSidebar
		bind:isOpen={isChatConfigOpen}
		chat={currentChat}
		{availablePersonas}
		on:settingsUpdated={(event) => {
			console.log('Chat settings updated:', event.detail);
		}}
		on:personaChanged={(event) => {
			console.log('Persona changed:', event.detail);
		}}
	/>
{/if}
