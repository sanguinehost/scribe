<script lang="ts">
	// Removed Attachment import
	import { toast } from 'svelte-sonner';
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import ChatHeader from './chat-header.svelte';
	import type { User, ScribeCharacter } from '$lib/types'; // Updated import path & Add ScribeCharacter
	import type { ScribeChatSession, ScribeChatMessage } from '$lib/types'; // Import Scribe types
	import Messages from './messages.svelte';
	import MultimodalInput from './multimodal-input.svelte';
	import { untrack } from 'svelte'; // Remove incorrect effect import

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

	// State variables
	const currentInitialMessages = initialMessagesProp;
	const currentCharacter = characterProp;
	const currentChat = chat; // chat prop is also used in logic

	const chatHistory = ChatHistory.fromContext();

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

	// --- Scribe Backend Interaction Logic ---

	async function sendMessage(content: string) {
		// Use user.user_id instead of user.id
		if (!currentChat?.id || !user?.user_id) {
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
			user_id: user.user_id, // Use user.user_id
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
			const response = await fetch(`/api/chats/${currentChat.id}/generate`, {
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
							// Append data, removing the 'data: ' prefix and leading space
							// Handle potential multi-line data correctly
							currentData += line.substring(5).trimStart() + (messageBlock.includes('\n') ? '\n' : '');
						}
					}
					currentData = currentData.trimEnd(); // Trim trailing newline if added

					// Process the completed event data
					if (currentData === '[DONE]') {
						console.log('SSE stream finished with [DONE] signal.');
						// Finalize the message state after the loop finishes naturally
						// No need to break here, let reader.read() return done: true
					} else if (currentEvent === 'error') {
						// Handle explicit error events from the backend
						console.error('SSE Error Event:', currentData);
						error = `Stream error: ${currentData}`; // Set local error state
						toast.error(error);
						reader.cancel('SSE error event received'); // Cancel the reader
						throw new Error(error); // Throw to trigger catch block and stop processing
					} else if (currentEvent === 'thinking') {
						// Handle thinking events if backend sends them (currently it doesn't)
						console.log('SSE Thinking Event:', currentData);
					} else if (currentData) {
						// Assume any other non-empty data is our JSON payload
						try {
							const parsedData = JSON.parse(currentData);
							if (parsedData && typeof parsedData.text === 'string') {
								messages = messages.map(msg =>
									msg.id === assistantMessageId
										? { ...msg, content: msg.content + parsedData.text }
										: msg
								);
							} else {
								console.warn('Received SSE data object without expected "text" field:', parsedData);
							}
						} catch (parseError: any) {
							console.error('Failed to parse SSE data as JSON:', currentData, parseError);
							// Decide how to handle parse errors: stop stream or log and continue?
							// For now, log and continue, but consider stopping if it's critical.
							// error = `Stream error: Invalid data format received.`;
							// toast.error(error);
							// reader.cancel('Invalid SSE data format');
							// throw new Error(error);
						}
					}
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
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
	<!-- ChatHeader type mismatch fixed by updating ChatHeader component -->
	<ChatHeader {user} {chat} {readonly} />
	<Messages
		{readonly}
		loading={isLoading}
		messages={messages}
	/>

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
