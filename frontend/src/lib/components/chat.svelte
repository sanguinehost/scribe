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
	// let attachments = $state<Attachment[]>([]);
	// let attachments = $state<any[]>([]); // State for attachments (currently unused) - REMOVED
	let chatInput = $state(''); // Input state managed here
	let currentAbortController = $state<AbortController | null>(null); // For cancelling stream

	// --- Scribe Backend Interaction Logic ---

	async function sendMessage(content: string) {
		if (!chat?.id || !user?.id) {
			error = 'Chat session or user information is missing.';
			toast.error(error);
			return;
		}

		isLoading = true;
		error = null;

		// Add user message optimistically
		const userMessage: ScribeChatMessage = {
			id: crypto.randomUUID(),
			session_id: chat.id,
			message_type: 'User',
			content: content,
			created_at: new Date().toISOString(),
			user_id: user.id,
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
			user_id: '', // Placeholder, backend should provide if needed (usually not for assistant)
			loading: true,
		};
		messages = [...messages, assistantMessage];

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

			while (true) {
				const { value, done } = await reader.read();
				if (done) {
					break;
				}
				buffer += decoder.decode(value, { stream: true });

				// Process buffer line by line for SSE messages
				const lines = buffer.split('\n');
				buffer = lines.pop() ?? ''; // Keep potential partial line

				for (const line of lines) {
					if (line.startsWith('data:')) {
						const dataContent = line.substring(5).trim();
						if (dataContent === '[DONE]') { // Check for a potential DONE signal if backend sends one
							console.log('Stream finished with [DONE]');
							break; // Or handle completion differently
						}
						try {
							const chunk = JSON.parse(dataContent);
							if (chunk.delta) {
								// Find the assistant message and append delta
								messages = messages.map(msg =>
									msg.id === assistantMessageId
										? { ...msg, content: msg.content + chunk.delta }
										: msg
								);
							}
						} catch (e) {
							console.error('Failed to parse SSE data chunk:', dataContent, e);
						}
					}
				}
			}

			// Finalize assistant message state
			messages = messages.map(msg =>
				msg.id === assistantMessageId ? { ...msg, loading: false } : msg
			);

		} catch (err: any) {
			if (err.name === 'AbortError') {
				console.log('Fetch aborted by user.');
				toast.info('Generation stopped.');
				// Remove the placeholder assistant message if aborted early
				messages = messages.filter(msg => msg.id !== assistantMessageId);
			} else {
				error = err.message || 'An unexpected error occurred.';
				toast.error(error ?? 'Unknown error'); // Ensure non-null string for toast
				// Remove placeholder assistant message on error
				messages = messages.filter(msg => msg.id !== assistantMessageId);
				// Optionally remove optimistic user message on error
				// messages = messages.filter(m => m.id !== userMessage.id);
			}
		} finally {
			isLoading = false;
			currentAbortController = null; // Clear the controller
			await chatHistory.refetch(); // Refetch history after interaction
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
