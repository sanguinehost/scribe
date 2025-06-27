<script lang="ts">
	// Removed Attachment import
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api'; // Import apiClient
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import ChatHeader from './chat-header.svelte';
	import type { User, ScribeCharacter } from '$lib/types.ts'; // Updated import path & Add ScribeCharacter
	import type { ScribeChatSession, ScribeChatMessage, ChatMode } from '$lib/types'; // Import Scribe types
	import type { UserPersona } from '$lib/types';
	import { createChatModeStrategy } from '$lib/strategies/chat';
	import Messages from './messages.svelte';
	import MultimodalInput from './multimodal-input.svelte';
	import SuggestedActions from './suggested-actions.svelte'; // Import SuggestedActions
	import ChatConfigSidebar from './chat-config-sidebar.svelte';
	// Removed untrack import as we no longer use it
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import TokenUsageDisplay from './token-usage-display.svelte';
	import { useTokenCounter } from '$lib/hooks/token-counter.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { streamingService, type StreamingMessage } from '$lib/services/StreamingService.svelte';

	// Get reactive state from streaming service
	// By directly accessing the $state properties of the service, we ensure reactivity.
	// const streamingState = $derived(streamingService.getState());

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

	// Load typing speed from user settings and sync with StreamingService
	$effect(() => {
		settingsStore.loadTypingSpeed();
		// Update StreamingService with user's typing speed preference
		streamingService.setTypingSpeed(settingsStore.typingSpeed);
	});

	// Clear selected character and persona when we have a chat
	$effect(() => {
		if (chat?.id) {
			selectedCharacterStore.clear();
			selectedPersonaStore.clear();
		}
	});

	// --- Scribe Chat State Management ---
	// The StreamingService is now the single source of truth for messages.
	// This component will populate the service with initial messages on load,
	// and derive its display messages directly from the service's state.


	// Message variants storage: messageId -> array of variant contents
	let messageVariants = $state<Map<string, { content: string; timestamp: string }[]>>(new Map());
	let currentVariantIndex = $state<Map<string, number>>(new Map());

	// This single effect handles both populating messages for the current chat
	// and cleaning them up when the chat changes or the component is destroyed.
	let previousChatId = $state<string | null>(null);
	
	$effect(() => {
		const currentChatId = chat?.id;
		console.log('CHAT EFFECT RUNNING. Chat ID:', currentChatId, 'Previous Chat ID:', previousChatId, 'Initial Messages Count:', initialMessages.length);

		// Only proceed if the chat ID has actually changed AND we have meaningful data
		// Avoid running on initial undefined states
		if (currentChatId !== previousChatId && (currentChatId || previousChatId)) {
			// Clear messages for previous chat if switching chats
			if (previousChatId && currentChatId !== previousChatId) {
				console.log(`Clearing messages for previous chat: ${previousChatId}`);
				streamingService.clearMessages();
			}
			
			if (currentChatId) {
				console.log('Populating messages for chat:', currentChatId);
				let newInitialMessages: StreamingMessage[];

				if (initialMessages.length === 0 && character?.first_mes) {
					const firstMessageId = `first-message-${currentChatId}`;
					newInitialMessages = [
						{
							id: firstMessageId,
							sender: 'assistant',
							content: character.first_mes,
							created_at: chat.created_at ?? new Date().toISOString(),
							loading: false
						}
					];
					console.log('Populating with character first message.');
				} else {
					newInitialMessages = initialMessages.map(
						(msg) =>
							({
								id: msg.id,
								sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
								content: msg.content,
								created_at: msg.created_at ?? new Date().toISOString(),
								loading: false,
								error: msg.error,
								retryable: msg.retryable,
								prompt_tokens: msg.prompt_tokens,
								completion_tokens: msg.completion_tokens,
								model_name: msg.model_name,
								backend_id: msg.backend_id
							}) as StreamingMessage
					);
					console.log(`Populating with ${newInitialMessages.length} initial messages.`);
				}
				// Clear and populate messages to ensure reactivity
				streamingService.clearMessages();
				for (const message of newInitialMessages) {
					streamingService.messages.push(message);
				}
				console.log('streamingService.messages populated. Count:', streamingService.messages.length);
				console.log('Verifying - streamingService.messages.length after assignment:', streamingService.messages.length);
			}
			
			// Update the previous chat ID
			previousChatId = currentChatId || null;
		}
	});
	
	// Separate effect for cleanup when component unmounts
	// This needs to track the chat ID to prevent clearing on every render
	$effect(() => {
		const currentChatId = chat?.id;
		
		return () => {
			// Only clear if we actually had a chat
			if (currentChatId) {
				console.log('COMPONENT CLEANUP: Clearing messages on unmount for chat:', currentChatId);
				streamingService.clearMessages();
			}
		};
	});

	// Sync loading state with StreamingService
	let isLoading = $derived(
		streamingService.connectionStatus === 'connecting' ||
			streamingService.connectionStatus === 'open'
	);
	
	// Watch for streaming completion
	$effect(() => {
		if (streamingService.connectionStatus === 'closed') {
			console.log('✅ StreamingService connection completed (status: closed)');
			// Force a re-render by updating the displayMessages derivation
			// The messages should already have loading: false set by finalizeMessage
			console.log('Current messages loading states:', streamingService.messages.map(m => ({ id: m.id, loading: m.loading })));
		}
	});

	// Create a single, reactive source of truth for display messages
	let displayMessages = $derived.by(() => {
		const streamingMessages = streamingService.messages;
		console.log('DERIVED `displayMessages` RECALCULATING. Message count:', streamingMessages.length);
		
		const messages = streamingMessages.map(
			(msg): ScribeChatMessage => ({
				id: msg.id,
				session_id: chat?.id ?? 'unknown-session',
				message_type: msg.sender === 'user' ? 'User' : 'Assistant',
				content: msg.content,
				created_at: msg.created_at,
				user_id: msg.sender === 'user' ? user?.id ?? '' : '',
				loading: msg.loading ?? false,
				error: msg.error,
				retryable: msg.retryable ?? false,
				prompt_tokens: msg.prompt_tokens,
				completion_tokens: msg.completion_tokens,
				model_name: msg.model_name,
				backend_id: msg.backend_id
			})
		);
		console.log('DERIVED `displayMessages` RECALCULATED. Count:', messages.length);
		return messages;
	});

	// Removed attachments state as feature is disabled/not supported
	let chatInput = $state(initialChatInputValue || ''); // Initialize with prop

	// --- Suggested Actions State ---
	let dynamicSuggestedActions = $state<Array<{ action: string }>>([]);
	let isLoadingSuggestions = $state(false);
	let suggestionsError = $state<string | null>(null);
	let suggestionsRetryable = $state(false);


	// --- Impersonate Response State ---
	// Removed - impersonate now directly sets input text

	// --- Chat Config Sidebar State ---
	let isChatConfigOpen = $state(false);

	// --- Token Counter State ---
	const tokenCounter = useTokenCounter();
	let showTokenUsage = $state(false);
	
	// --- Cumulative Usage Tracking ---
	let cumulativeTokens = $state({
		input: 0,
		output: 0,
		total: 0,
		cost: 0 // Added cumulative cost
	});

	// Track suggested actions token usage
	let suggestedActionsTokens = $state({
		input: 0,
		output: 0,
		total: 0,
		cost: 0
	});

	// Pricing per model (per 1M tokens)
	const modelPricing = {
		'gemini-2.5-flash': { input: 0.30, output: 2.50 },
		'gemini-2.5-pro': { input: 1.25, output: 10.00 },
		'gemini-2.5-flash-lite-preview': { input: 0.10, output: 0.40 }
	};

	// Calculate cumulative usage from messages (backend already includes system context)
	// Exclude first messages since they're pre-written content, not AI-generated
	$effect(() => {
		let inputTokens = 0;
		let outputTokens = 0;
		let totalCost = 0;
		
		displayMessages.forEach(message => {
			// Skip first messages (character greetings) - they shouldn't count toward usage
			const isFirstMessage = message.id.startsWith('first-message-') || 
				(message.message_type === 'Assistant' && message.content === character?.first_mes);
			
			if (!isFirstMessage) {
				const messageInputTokens = message.prompt_tokens || 0;
				const messageOutputTokens = message.completion_tokens || 0;
				
				if (messageInputTokens > 0 || messageOutputTokens > 0) {
					inputTokens += messageInputTokens;
					outputTokens += messageOutputTokens;
					
					// Calculate cost using the model used for THIS specific message
					const messageModel = message.model_name || chat?.model_name || 'gemini-2.5-pro';
					const pricing = modelPricing[messageModel as keyof typeof modelPricing] || { input: 1.25, output: 10.00 };
					
					const messageCost = (messageInputTokens / 1_000_000 * pricing.input) + 
									   (messageOutputTokens / 1_000_000 * pricing.output);
					totalCost += messageCost;
				}
			}
		});
		
		cumulativeTokens = {
			input: inputTokens + suggestedActionsTokens.input,
			output: outputTokens + suggestedActionsTokens.output,
			total: inputTokens + outputTokens + suggestedActionsTokens.total,
			cost: totalCost + suggestedActionsTokens.cost
		};
		
		// Token calculation completed
	});
	let availablePersonas = $state<UserPersona[]>([]);

	// --- State for chat interface visibility ---
	// The chat interface visibility now depends on the chat mode strategy
	let shouldShowChatInterface = $state(false);

	// Create strategy based on chat mode
	let chatModeStrategy = $derived.by(() => {
		if (!chat) return null;
		
		// Check if chat_mode exists and is valid
		if (!chat.chat_mode) {
			console.error('Chat object missing chat_mode field:', chat);
			return null;
		}
		
		try {
			return createChatModeStrategy(chat.chat_mode);
		} catch (error) {
			console.error('Failed to create chat mode strategy:', error, 'for mode:', chat.chat_mode);
			return null;
		}
	});

	// Create derived placeholder text
	let placeholderText = $derived.by(() => {
		const strategy = chatModeStrategy;
		if (!strategy) return "Send a message...";
		return strategy.getMessageInputPlaceholder(character || null);
	});

	// Update visibility when props change using the strategy pattern
	$effect(() => {
		const strategy = chatModeStrategy;
		if (!strategy) {
			shouldShowChatInterface = false;
			return;
		}

		// Additional safety check - ensure the strategy function exists
		if (typeof strategy.shouldShowChatInterface !== 'function') {
			console.error('Strategy does not have shouldShowChatInterface method:', strategy);
			shouldShowChatInterface = false;
			return;
		}

		const shouldShow = strategy.shouldShowChatInterface(chat || null, character || null);

		// Debug logging for tests and development
		if (process.env.NODE_ENV === 'test') {
			console.log('shouldShowChatInterface effect update:', {
				chat_mode: chat?.chat_mode,
				shouldShow,
				chat_id: chat?.id || 'undefined',
				character_id: character?.id || 'undefined',
				strategy: strategy.constructor.name
			});
		}

		shouldShowChatInterface = shouldShow;
	});

	// Button is enabled when we can actually fetch suggestions (same as interface visibility)
	let canFetchSuggestions = $derived.by(() => {
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

	// --- Token Counting Effect ---
	let tokenCountTimeout: NodeJS.Timeout | null = null;

	$effect(() => {
		// Debounce token counting to avoid excessive API calls
		if (tokenCountTimeout) {
			clearTimeout(tokenCountTimeout);
		}

		if (chatInput.trim().length > 0) {
			tokenCountTimeout = setTimeout(async () => {
				try {
					const model = await getCurrentChatModel();
					const result = await tokenCounter.countTokensSimple(chatInput.trim(), model || undefined, false);
					// Only show if we actually got a meaningful result
					showTokenUsage = !!(result && result.total > 0);
				} catch (error) {
					console.error('Token counting failed:', error);
					showTokenUsage = false;
				}
			}, 500); // 500ms debounce
		} else {
			tokenCounter.reset();
			showTokenUsage = false;
		}
	});

	// --- Scribe Backend Interaction Logic ---

	// --- Chronicle Creation Logic ---

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
			suggestionsError = null;
			suggestionsRetryable = false;
			
			const result = await apiClient.fetchSuggestedActions(chat.id);

			if (result.isOk()) {
				const responseData = result.value; // This is { suggestions: [...], token_usage?: {...} }
				if (responseData.suggestions && responseData.suggestions.length > 0) {
					dynamicSuggestedActions = responseData.suggestions;
					console.log('Successfully fetched suggested actions:', dynamicSuggestedActions);
				} else {
					console.log('No suggestions returned or suggestions array is empty.');
					dynamicSuggestedActions = [];
				}

				// Track token usage for suggested actions
				if (responseData.token_usage) {
					const tokenUsage = responseData.token_usage;
					// Use Flash pricing since suggested actions always use gemini-2.5-flash
					const flashPricing = modelPricing['gemini-2.5-flash'];
					const cost = (tokenUsage.input_tokens / 1_000_000 * flashPricing.input) + 
								(tokenUsage.output_tokens / 1_000_000 * flashPricing.output);

					suggestedActionsTokens = {
						input: tokenUsage.input_tokens,
						output: tokenUsage.output_tokens,
						total: tokenUsage.total_tokens,
						cost
					};

					console.log('Suggested actions token usage:', {
						input: tokenUsage.input_tokens,
						output: tokenUsage.output_tokens,
						total: tokenUsage.total_tokens,
						cost: cost.toFixed(4)
					});
				}
			} else {
				const error = result.error;
				console.error('Error fetching suggested actions:', error.message);
				
				// Clean up error message for user display
				let cleanErrorMessage = error.message;
				if (error.message.includes('PropertyNotFound("/content/parts")') || error.message.includes('PropertyNotFound("/candidates")')) {
					cleanErrorMessage = 'AI safety filters blocked the suggestion request. Try again or continue chatting.';
				} else if (error.message.includes('Failed to parse stream data') || error.message.includes('trailing characters')) {
					cleanErrorMessage = 'AI service returned malformed data. Please try again.';
				} else if (error.message.includes('Gemini API error:')) {
					// Remove redundant "Gemini API error:" prefix
					cleanErrorMessage = error.message.replace('Gemini API error: ', '');
				}
				
				suggestionsError = cleanErrorMessage;
				suggestionsRetryable = true;
				dynamicSuggestedActions = [];
				toast.error(`Could not load suggested actions: ${cleanErrorMessage}`);
			}
		} catch (err: any) {
			// Catch any unexpected errors during the API client call itself
			console.error('Error fetching suggested actions:', err);
			
			// Clean up error message for user display
			let cleanErrorMessage = err.message || 'An unexpected error occurred.';
			if (cleanErrorMessage.includes('PropertyNotFound("/content/parts")') || cleanErrorMessage.includes('PropertyNotFound("/candidates")')) {
				cleanErrorMessage = 'AI safety filters blocked the suggestion request. Try again or continue chatting.';
			} else if (cleanErrorMessage.includes('Failed to parse stream data') || cleanErrorMessage.includes('trailing characters')) {
				cleanErrorMessage = 'AI service returned malformed data. Please try again.';
			}
			
			suggestionsError = cleanErrorMessage;
			suggestionsRetryable = true;
			dynamicSuggestedActions = [];
			toast.error(`Could not load suggested actions: ${cleanErrorMessage}`);
		} finally {
			isLoadingSuggestions = false;
		}
	}

	async function sendMessage(content: string) {
		dynamicSuggestedActions = []; // Clear suggestions when a message (including a suggestion) is sent

		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Build history from the single source of truth
		const existingHistoryForApi = (streamingService.messages as StreamingMessage[])
			.filter((m) => !m.loading)
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		try {
			// Use StreamingService for the connection
			const currentModel = await getCurrentChatModel();
			console.log('🚀 Starting StreamingService connection:', {
				chatId: chat.id,
				userMessage: content,
				historyLength: existingHistoryForApi.length,
				model: currentModel
			});
			await streamingService.connect({
				chatId: chat.id,
				userMessage: content,
				history: existingHistoryForApi,
				model: currentModel || undefined
			});
			console.log('✅ StreamingService.connect() called (streaming in progress)');
		} catch (error) {
			console.error('❌ Failed to send message:', error);
			toast.error('Failed to send message. Please try again.');
		}
	}

	// Generate AI response based on current messages (used for edited messages)
	async function generateAIResponse() {
		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Build history from current messages
		const historyToSend = (streamingService.messages as StreamingMessage[])
			.filter((m) => !m.loading)
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		try {
			// Use StreamingService - it will handle the last user message from history
			const lastUserMessage = historyToSend.filter(h => h.role === 'user').pop();
			if (!lastUserMessage) {
				toast.error('No user message found to generate response.');
				return;
			}

			const currentModel = await getCurrentChatModel();
			await streamingService.connect({
				chatId: chat.id,
				userMessage: lastUserMessage.content,
				history: historyToSend.slice(0, -1), // Exclude the last user message since it's passed separately
				model: currentModel || undefined
			});
		} catch (error) {
			console.error('Failed to generate AI response:', error);
			toast.error('Failed to generate response. Please try again.');
		}
	}

	function stopGeneration() {
		streamingService.disconnect();
	}

	// Input submission handler
	function handleInputSubmit(e: Event) {
		e.preventDefault();
		if (chatInput.trim() && !isLoading) {
			sendMessage(chatInput.trim());
			chatInput = ''; // Clear input after sending
		}
	}

	// Regenerate AI response without adding a new user message - using StreamingService
	async function regenerateResponse(_userMessageContent: string, _originalMessageId?: string) {
		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Check if currently loading
		if (isLoading) {
			toast.warning('Please wait for the current message to complete.');
			return;
		}

		// Build the history - messages array already has the right messages after we removed the assistant message
		// Just convert to API format
		const historyToSend = (streamingService.messages as StreamingMessage[])
			.filter((m) => !m.loading)
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		// Find the last user message to regenerate response for
		const lastUserMessage = historyToSend.filter(h => h.role === 'user').pop();
		if (!lastUserMessage) {
			toast.error('No user message found to regenerate response.');
			return;
		}

		try {
			// Use StreamingService for regeneration - it will handle the streaming
			const currentModel = await getCurrentChatModel();
			await streamingService.connect({
				chatId: chat.id,
				userMessage: lastUserMessage.content,
				history: historyToSend.slice(0, -1), // Exclude the last user message since it's passed separately
				model: currentModel || undefined
			});

			// Update chat preview after successful regeneration
			// Note: StreamingService will handle message creation and updates
			const preview = lastUserMessage.content.substring(0, 100);
			chatHistory.updateChatPreview(chat.id, preview);
		} catch (error) {
			console.error('Failed to regenerate response:', error);
			toast.error('Failed to regenerate response. Please try again.');
		}
	}

	// Handle greeting changes from alternate greetings
	function handleGreetingChanged(detail: { index: number; content: string }) {
		const { content } = detail;

		// Update the first message content in the messages array
		const firstMessageId = `first-message-${chat?.id ?? 'initial'}`;
		streamingService.messages = (streamingService.messages as StreamingMessage[]).map((msg) =>
			msg.id === firstMessageId ? { ...msg, content } : msg
		);
	}

	// Message action handlers
	async function handleRetryMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Retry message:', messageId);

		// Find the assistant message to retry
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex((msg) => msg.id === messageId);
		if (messageIndex === -1) return;

		const targetMessage = (streamingService.messages as StreamingMessage[])[messageIndex];
		if (targetMessage.sender !== 'assistant') return;

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

		const userMessage = (streamingService.messages as StreamingMessage[])[userMessageIndex];
		if (userMessage.sender !== 'user') return;

		// Remove the assistant message and any messages after it
		const allMessages = [...(streamingService.messages as StreamingMessage[])];
		const removedMessages = allMessages.slice(messageIndex);
		streamingService.messages = allMessages.slice(0, messageIndex);

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
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex((msg) => msg.id === messageId);
		if (messageIndex === -1) return;

		const targetMessage = (streamingService.messages as StreamingMessage[])[messageIndex];
		if (targetMessage.sender !== 'user') return;

		// Update the message content
		const allMessages = [...(streamingService.messages as StreamingMessage[])];
		allMessages[messageIndex].content = newContent;

		// Get messages that will be removed for backend cleanup
		const removedMessages = allMessages.slice(messageIndex + 1);

		// Clear all subsequent messages (everything after this user message)
		streamingService.messages = allMessages.slice(0, messageIndex + 1);

		// Clear any variant data for removed messages
		const keptMessageIds = new Set(streamingService.messages.map((m: StreamingMessage) => m.id));
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
			streamingService.messages = (streamingService.messages as StreamingMessage[]).map((msg) => {
				if (msg.id === messageId) {
					return { ...msg, content: variants[newIndex].content };
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

			streamingService.messages = (streamingService.messages as StreamingMessage[]).map((msg) => {
				if (msg.id === messageId) {
					return { ...msg, content: variants[newIndex].content };
				}
				return msg;
			});
		} else {
			// No more variants, generate a new one
			handleRetryMessage(messageId);
		}
	}

	// Retry a failed assistant message
	async function handleRetryFailedMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Retry failed message:', messageId);

		// Find the failed assistant message
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex((msg) => msg.id === messageId);
		if (messageIndex === -1) return;

		const failedMessage = (streamingService.messages as StreamingMessage[])[messageIndex];
		if (failedMessage.sender !== 'assistant' || !failedMessage.error) return;

		// Find the previous user message to regenerate from
		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = (streamingService.messages as StreamingMessage[])[userMessageIndex];
		if (userMessage.sender !== 'user') return;

		// Clear the error state and set to loading
		const allMessages = [...(streamingService.messages as StreamingMessage[])];
		allMessages[messageIndex] = {
			...allMessages[messageIndex],
			loading: true,
			error: undefined,
			retryable: false,
			content: ''
		};

		// Remove any messages after the failed one (they were dependent on the failed generation)
		const messagesToRemove = allMessages.slice(messageIndex + 1);
		streamingService.messages = allMessages.slice(0, messageIndex + 1);

		// Clean up variant data for removed messages
		for (const removedMsg of messagesToRemove) {
			messageVariants.delete(removedMsg.id);
			currentVariantIndex.delete(removedMsg.id);
		}

		// Delete trailing messages from backend if they exist
		if (messagesToRemove.length > 0 && messagesToRemove[0].backend_id) {
			try {
				await apiClient.deleteTrailingMessages(messagesToRemove[0].backend_id);
			} catch (err) {
				console.warn('Failed to delete trailing messages from backend during retry:', err);
				// Continue with retry even if cleanup fails
			}
		}

		// Regenerate the response using the same logic as normal generation
		// Use the existing regenerateResponse function
		regenerateResponse(userMessage.content, messageId);
	}

	async function handleDeleteMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Delete message:', messageId);

		// Find the message to delete
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex((msg) => msg.id === messageId);
		if (messageIndex === -1) return;

		// Get the message before removing it
		const messageToDelete = (streamingService.messages as StreamingMessage[])[messageIndex];

		// Remove the message from the UI immediately
		const allMessages = [...(streamingService.messages as StreamingMessage[])];
		allMessages.splice(messageIndex, 1);
		streamingService.messages = allMessages;

		// Clean up variant data for deleted message
		messageVariants.delete(messageId);
		currentVariantIndex.delete(messageId);

		// Delete from backend if it has a backend ID
		if (messageToDelete?.backend_id || messageToDelete?.id) {
			try {
				await apiClient.deleteMessage(messageToDelete.backend_id || messageToDelete.id);
				console.log('Message deleted from backend successfully');
			} catch (err) {
				console.error('Failed to delete message from backend:', err);
				// Note: We don't revert the UI change since the user intended to delete it
				// They can refresh to see the actual state if needed
			}
		}
	}
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
	<!-- ChatHeader type mismatch fixed by updating ChatHeader component -->
	<ChatHeader {user} {chat} {readonly} />
	<Messages
		{readonly}
		loading={isLoading}
		messages={displayMessages}
		selectedCharacterId={selectedCharacterStore.characterId}
		{character}
		{chat}
		{user}
		{messageVariants}
		{currentVariantIndex}
		onRetryMessage={handleRetryMessage}
		onRetryFailedMessage={handleRetryFailedMessage}
		onEditMessage={handleEditMessage}
		onSaveEditedMessage={handleSaveEditedMessage}
		onDeleteMessage={handleDeleteMessage}
		onPreviousVariant={handlePreviousVariant}
		onNextVariant={handleNextVariant}
		onGreetingChanged={handleGreetingChanged}
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


		<!-- Suggested Actions Error -->
		{#if suggestionsError && !isLoading && !isLoadingSuggestions}
			<div class="mx-auto w-full px-4 pb-2 md:max-w-3xl">
				<div class="rounded-md border border-red-200 bg-red-50 p-3 dark:border-red-800 dark:bg-red-950/20">
					<div class="flex items-start gap-3">
						<div class="flex-shrink-0 text-red-500 mt-0.5">
							<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
								<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
							</svg>
						</div>
						<div class="flex-1">
							<p class="text-red-700 dark:text-red-300 font-medium text-sm">
								Failed to load suggestions
							</p>
							<p class="text-red-600 dark:text-red-400 text-sm mt-1">
								{suggestionsError}
							</p>
							{#if suggestionsRetryable}
								<div class="flex gap-2 mt-3">
									<button
										type="button"
										onclick={() => {
											suggestionsError = null;
											suggestionsRetryable = false;
											fetchSuggestedActions();
										}}
										class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-700 bg-red-100 border border-red-300 rounded-md hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-1 dark:text-red-300 dark:bg-red-950/30 dark:border-red-700 dark:hover:bg-red-950/50"
									>
										<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
										</svg>
										Retry
									</button>
									<button
										type="button"
										onclick={() => {
											suggestionsError = null;
											suggestionsRetryable = false;
										}}
										class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-700 bg-gray-100 border border-gray-300 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-1 dark:text-gray-300 dark:bg-gray-800 dark:border-gray-600 dark:hover:bg-gray-700"
									>
										Dismiss
									</button>
								</div>
							{/if}
						</div>
					</div>
				</div>
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
						placeholder={placeholderText}
						onImpersonate={(response) => {
							chatInput = response;
						}}
					/>
					
					<!-- Token Usage Display -->
					{#if showTokenUsage && tokenCounter.data}
						<div class="mt-2 flex justify-end">
							<TokenUsageDisplay 
								promptTokens={tokenCounter.data.total}
								completionTokens={0}
								modelName={chat?.model_name}
								loading={tokenCounter.loading}
								isEstimate={true}
							/>
						</div>
					{/if}
					
					<!-- Cumulative Session Usage Display -->
					{#if cumulativeTokens.total > 0}
						{@const formatSessionCost = (cost: number) => cost < 0.0001 ? '<$0.0001' : `$${cost.toFixed(4)}`}
						
						<div class="mt-2 space-y-1 text-xs text-muted-foreground border-t pt-2">
							<!-- Main breakdown -->
							<div class="flex justify-between items-center">
								<span class="font-medium">Session Usage:</span>
								<div class="flex items-center gap-2">
									<span class="text-blue-600 dark:text-blue-400">
										↑{cumulativeTokens.input} input
									</span>
									<span class="text-green-600 dark:text-green-400">
										↓{cumulativeTokens.output} output
									</span>
									<span class="font-medium">
										{cumulativeTokens.total} total
									</span>
									<span class="text-amber-600 dark:text-amber-400 font-mono font-medium">
										{formatSessionCost(cumulativeTokens.cost)}
									</span>
								</div>
							</div>
							
							<!-- Note about system context -->
							<div class="text-center text-xs opacity-75">
								Hover messages for individual token counts & costs • Using per-message model pricing
							</div>
						</div>
					{/if}
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
