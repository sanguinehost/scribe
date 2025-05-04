<script lang="ts">
	// Removed Attachment import
	import { toast } from 'svelte-sonner';
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import ChatHeader from './chat-header.svelte';
	import type { User } from '$lib/types'; // Updated import path
	import type { ScribeChatSession, ScribeChatMessage } from '$lib/types'; // Import Scribe types
	import Messages from './messages.svelte';
	import MultimodalInput from './multimodal-input.svelte';
	import { untrack } from 'svelte';

	let {
		user,
		chat,
		readonly,
		initialMessages
	}: {
		user: User | undefined;
		chat: ScribeChatSession | undefined;
		initialMessages: ScribeChatMessage[];
		readonly: boolean;
	} = $props();

	const chatHistory = ChatHistory.fromContext();

	// Scribe chat state management
	let messages = $state<ScribeChatMessage[]>(initialMessages);
	let isLoading = $state(false);
	let error = $state<string | null>(null); // Add error state

	// Removed attachments state as feature is disabled/not supported
	let chatInput = $state(''); // Input state managed here
	let currentAbortController = $state<AbortController | null>(null); // For cancelling stream

	// --- Scribe Backend Interaction Logic ---

	async function sendMessage(content: string) {
		// Use user.user_id instead of user.id
		if (!chat?.id || !user?.user_id) {
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
			user_id: user.user_id, // Use user.user_id
			loading: false,
		};
		messages = [...messages, userMessage];

		// --- SSE Handling using Fetch API ---
		currentAbortController = new AbortController();
		const signal = currentAbortController.signal;

		// Add placeholder for assistant message
		const assistantMessageId = crypto.randomUUID();
		let assistantMessage: ScribeChatMessage = {
			id: assistantMessageId,
			session_id: chat.id,
			message_type: 'Assistant',
			content: '', // Start empty, fill with stream
			created_at: new Date().toISOString(), // Placeholder, backend might send final
			user_id: '', // Assistant messages don't have a user_id in the same way
			loading: true,
		};
		messages = [...messages, assistantMessage];

		let fetchError: any = null; // Variable to store error from fetch/parsing

		try {
			const response = await fetch(`/api/chats/${chat.id}/generate`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Accept': 'text/event-stream' // Indicate we want SSE
				},
				body: JSON.stringify({ content: content }),
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

					// Process the completed event
					if (currentEvent === 'content') {
						messages = messages.map(msg =>
							msg.id === assistantMessageId
								? { ...msg, content: msg.content + currentData }
								: msg
						);
					} else if (currentEvent === 'error') {
						console.error('SSE Error Event:', currentData);
						error = `Stream error: ${currentData}`; // Set local error state
						toast.error(error);
						reader.cancel('SSE error event received'); // Cancel the reader
						throw new Error(error); // Throw to trigger catch block and stop processing
					} else if (currentEvent === 'done' && currentData === '[DONE]') {
						console.log('Stream finished with event: done, data: [DONE]');
						// The loop will break naturally via reader.read() done flag
					} else if (currentEvent === 'thinking') {
						console.log('SSE Thinking Event:', currentData); // Log thinking steps if needed
						// Optionally update UI to show thinking state
					}
				}
			}

			// Handle any remaining data in the buffer after the loop (should be empty if stream ended cleanly)
			if (buffer.trim()) {
				console.warn('SSE stream ended with unprocessed buffer:', buffer);
			}

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
			console.log('Aborting fetch request...');
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
