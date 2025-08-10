<script lang="ts">
	// Removed Attachment import
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api'; // Import apiClient
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import { tick } from 'svelte';
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
	import ChronicleOptInDialog from './chronicle-opt-in-dialog.svelte';
	import { browser } from '$app/environment';

	// Get reactive state from streaming service
	// By directly accessing the $state properties of the service, we ensure reactivity.
	// const streamingState = $derived(streamingService.getState());

	let {
		user,
		chat,
		readonly,
		initialMessages,
		character,
		initialChatInputValue,
		initialCursor
	}: {
		user: User | undefined;
		chat: ScribeChatSession | undefined;
		initialMessages: ScribeChatMessage[];
		readonly: boolean;
		character: ScribeCharacter | null | undefined;
		initialChatInputValue?: string;
		initialCursor?: string | null;
	} = $props();

	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const settingsStore = SettingsStore.fromContext();

	// State variables - use props directly for reactivity
	// Note: In Svelte 5, props are already reactive, so we can use them directly

	const chatHistory = ChatHistory.fromContext();

	// Pagination state
	let nextCursor = $state<string | null>(initialCursor || null);
	let isLoadingMore = $state(false);
	let hasMoreMessages = $state(initialCursor !== null);
	let loadedMessagesBatches = $state<ScribeChatMessage[][]>([initialMessages]);
	let suppressAutoScroll = $state(false);

	// Chronicle opt-in state
	let showChronicleOptIn = $state(false);
	let pendingMessage = $state<string | null>(null);
	let chroniclePreference: boolean | null = $state(null);

	// Load typing speed from user settings and sync with StreamingService
	$effect(() => {
		settingsStore.loadTypingSpeed();
		// Update StreamingService with user's typing speed preference
		streamingService.setTypingSpeed(settingsStore.typingSpeed);
	});

	// Load saved chronicle preference from localStorage
	$effect(() => {
		if (browser) {
			const saved = localStorage.getItem('chroniclePreference');
			if (saved !== null) {
				chroniclePreference = saved === 'true';
			}
		}
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

		// Only react to chat ID changes, not batch count changes
		if (currentChatId !== previousChatId && (currentChatId || previousChatId)) {
			// Clear messages for previous chat if switching chats
			if (previousChatId && currentChatId !== previousChatId) {
				streamingService.clearMessages();

				// Reset pagination state when switching chats
				loadedMessagesBatches = [initialMessages];
				nextCursor = initialCursor || null;
				hasMoreMessages = initialCursor !== null;
				isLoadingMore = false;
			}

			if (currentChatId) {
				let newInitialMessages: StreamingMessage[];

				if (initialMessages.length === 0 && character?.first_mes) {
					const firstMessageId = `first-message-${currentChatId}`;
					newInitialMessages = [
						{
							id: firstMessageId,
							sender: 'assistant',
							content: character.first_mes,
							displayedContent: character.first_mes, // Show immediately for initial message
							created_at: chat.created_at ?? new Date().toISOString(),
							isAnimating: false // Initial messages don't animate
						}
					];
				} else {
					// Flatten all loaded batches into a single array
					const allLoadedMessages = loadedMessagesBatches.flat();
					newInitialMessages = allLoadedMessages.map(
						(msg) =>
							({
								id: msg.id,
								sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
								content: msg.content,
								displayedContent: msg.content, // Show immediately for existing messages
								created_at: msg.created_at ?? new Date().toISOString(),
								isAnimating: false, // Existing messages don't animate
								error: msg.error,
								retryable: msg.retryable,
								prompt_tokens: msg.prompt_tokens,
								completion_tokens: msg.completion_tokens,
								model_name: msg.model_name,
								backend_id: msg.backend_id
							}) as StreamingMessage
					);
				}
				// Clear and populate messages to ensure reactivity
				streamingService.clearMessages();
				for (const message of newInitialMessages) {
					streamingService.messages.push(message);
				}
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
				streamingService.clearMessages();
			}
		};
	});

	// Sync loading state with StreamingService
	// Include both SSE connection phase AND local animation phase
	let isLoading = $derived(
		streamingService.connectionStatus === 'connecting' ||
			streamingService.connectionStatus === 'open' ||
			streamingService.messages.some((msg) => msg.isAnimating === true)
	);

	// Load more messages function for infinite scroll
	async function loadMoreMessages() {
		if (!chat?.id || isLoadingMore || !hasMoreMessages || !nextCursor) {
			return;
		}

		isLoadingMore = true;
		suppressAutoScroll = true;

		try {
			const result = await apiClient.getMessagesByChatId(chat.id, {
				limit: 20,
				cursor: nextCursor
			});

			if (result.isErr()) {
				console.error('Failed to load more messages:', result.error);
				toast.error('Failed to load older messages');
				return;
			}

			// Handle paginated response
			if (!Array.isArray(result.value) && 'messages' in result.value) {
				const { messages: newMessages, nextCursor: newCursor } = result.value;

				console.log('📥 Loading more messages:', {
					newMessagesCount: newMessages.length,
					newCursor,
					currentStreamingCount: streamingService.messages.length
				});

				// Convert to ScribeChatMessage format
				const convertedMessages: ScribeChatMessage[] = newMessages.map(
					(rawMsg): ScribeChatMessage => ({
						id: rawMsg.id,
						backend_id: rawMsg.id,
						session_id: rawMsg.session_id,
						message_type: rawMsg.message_type,
						content:
							rawMsg.parts &&
							rawMsg.parts.length > 0 &&
							'text' in rawMsg.parts[0] &&
							typeof rawMsg.parts[0].text === 'string'
								? rawMsg.parts[0].text
								: '',
						created_at:
							typeof rawMsg.created_at === 'string'
								? rawMsg.created_at
								: rawMsg.created_at.toISOString(),
						user_id: '',
						loading: false,
						raw_prompt: rawMsg.raw_prompt,
						prompt_tokens: rawMsg.prompt_tokens,
						completion_tokens: rawMsg.completion_tokens,
						model_name: rawMsg.model_name
					})
				);

				// Get reference to messages container for scroll preservation
				const messagesContainer =
					document.querySelector('[data-messages-container]') ||
					document.querySelector('.overflow-y-scroll');

				if (messagesContainer) {
					// Store current scroll position relative to bottom
					const oldScrollTop = messagesContainer.scrollTop;
					const oldScrollHeight = messagesContainer.scrollHeight;
					const containerHeight = messagesContainer.clientHeight;
					const distanceFromBottom = oldScrollHeight - oldScrollTop - containerHeight;

					console.log('📍 Scroll position before:', {
						oldScrollTop,
						oldScrollHeight,
						containerHeight,
						distanceFromBottom
					});

					// Convert to StreamingMessage format and prepend to streaming service
					const streamingMessages = convertedMessages.map(
						(msg): StreamingMessage => ({
							id: msg.id,
							sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
							content: msg.content,
							displayedContent: msg.content,
							created_at: msg.created_at,
							isAnimating: false,
							error: msg.error,
							retryable: msg.retryable,
							prompt_tokens: msg.prompt_tokens,
							completion_tokens: msg.completion_tokens,
							model_name: msg.model_name,
							backend_id: msg.backend_id
						})
					);

					// Prepend the new messages to the beginning of the array (create new array reference)
					streamingService.messages = [...streamingMessages, ...streamingService.messages];

					console.log('✅ Added messages to streaming service:', {
						addedCount: streamingMessages.length,
						newTotalCount: streamingService.messages.length,
						firstNewMessage: streamingMessages[0]?.id,
						lastNewMessage: streamingMessages[streamingMessages.length - 1]?.id
					});

					// Add to loaded batches for tracking
					loadedMessagesBatches.push(convertedMessages);

					// Use tick to wait for DOM update
					await tick();

					// Calculate new scroll position to maintain same distance from bottom
					const newScrollHeight = messagesContainer.scrollHeight;
					const newContainerHeight = messagesContainer.clientHeight;
					const targetScrollTop = newScrollHeight - distanceFromBottom - newContainerHeight;

					console.log('📍 Scroll position after:', {
						newScrollHeight,
						newContainerHeight,
						targetScrollTop,
						heightAdded: newScrollHeight - oldScrollHeight
					});

					// Adjust scroll position to maintain the same relative position
					messagesContainer.scrollTop = targetScrollTop;

					// Add another tick and delay to ensure scroll position sticks
					await tick();
					setTimeout(() => {
						if (messagesContainer) {
							messagesContainer.scrollTop = targetScrollTop;
						}
						// Re-enable auto-scroll after scroll position is set
						suppressAutoScroll = false;
					}, 150);
				} else {
					// Fallback if we can't find the container
					const streamingMessages = convertedMessages.map(
						(msg): StreamingMessage => ({
							id: msg.id,
							sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
							content: msg.content,
							displayedContent: msg.content,
							created_at: msg.created_at,
							isAnimating: false,
							error: msg.error,
							retryable: msg.retryable,
							prompt_tokens: msg.prompt_tokens,
							completion_tokens: msg.completion_tokens,
							model_name: msg.model_name,
							backend_id: msg.backend_id
						})
					);

					streamingService.messages = [...streamingMessages, ...streamingService.messages];
					loadedMessagesBatches.push(convertedMessages);
				}

				// Update cursor and hasMore state
				nextCursor = newCursor;
				hasMoreMessages = newCursor !== null;
			}
		} catch (error) {
			console.error('Error loading more messages:', error);
			toast.error('Failed to load older messages');
		} finally {
			isLoadingMore = false;
			// Ensure suppressAutoScroll is cleared even if there's an error
			if (suppressAutoScroll) {
				setTimeout(() => {
					suppressAutoScroll = false;
				}, 200);
			}
		}
	}

	// Watch for streaming completion - DISABLED to prevent refresh issues
	// $effect(() => {
	// 	if (streamingService.connectionStatus === 'closed') {
	// 		console.log('✅ StreamingService connection completed (status: closed) - REFRESH DISABLED');
	// 		// DISABLED: Force a re-render by updating the displayMessages derivation
	// 		// The messages should already have loading: false set by finalizeMessage
	// 		console.log('Current messages loading states:', streamingService.messages.map(m => ({ id: m.id, loading: m.loading })));
	// 	}
	// });

	// Object identity cache to prevent unnecessary component recreation
	let messageCache = new Map<string, ScribeChatMessage>();
	let lastStreamingMessages: any[] = [];

	// Create a single, reactive source of truth for display messages with object identity preservation
	let displayMessages = $derived.by(() => {
		const streamingMessages = streamingService.messages;
		console.log('🔄 displayMessages derived:', {
			streamingCount: streamingMessages.length,
			firstMessage: streamingMessages[0]?.id,
			lastMessage: streamingMessages[streamingMessages.length - 1]?.id
		});

		// Check if messages array actually changed to avoid unnecessary work
		if (streamingMessages === lastStreamingMessages) {
			console.log('⚠️ displayMessages: Using cached result, no change detected');
			return Array.from(messageCache.values());
		}

		console.log('🔄 displayMessages: Processing new messages array');

		const messages: ScribeChatMessage[] = [];
		const newCache = new Map<string, ScribeChatMessage>();

		streamingMessages.forEach((msg) => {
			const cached = messageCache.get(msg.id);

			// Check if message content/state actually changed (NEW: using displayedContent and isAnimating)
			const isAnimatingOrLoading = msg.isAnimating ?? false;
			const displayContent = msg.displayedContent ?? msg.content; // Fallback to full content if no displayedContent

			const hasChanged =
				!cached ||
				cached.loading !== isAnimatingOrLoading ||
				cached.content !== displayContent ||
				cached.prompt_tokens !== msg.prompt_tokens ||
				cached.completion_tokens !== msg.completion_tokens ||
				cached.error !== msg.error;

			if (hasChanged) {
				// Only log when not animating to avoid spam
				if (!msg.isAnimating) {
					console.log(
						`🔄 Message ${msg.id.slice(-8)} changed - displayed: ${displayContent.length}chars, full: ${msg.content.length}chars, tokens: ${msg.prompt_tokens}/${msg.completion_tokens}`
					);
				}

				// Create new message object only if changed (NEW: using displayedContent for UI)
				const newMessage: ScribeChatMessage = {
					id: msg.id,
					session_id: chat?.id ?? 'unknown-session',
					message_type: msg.sender === 'user' ? ('User' as const) : ('Assistant' as const),
					content: displayContent, // Use displayedContent for UI rendering
					created_at: msg.created_at,
					user_id: msg.sender === 'user' ? (user?.id ?? '') : '',
					loading: isAnimatingOrLoading, // Use isAnimating for loading state
					error: msg.error,
					retryable: msg.retryable ?? false,
					prompt_tokens: msg.prompt_tokens,
					completion_tokens: msg.completion_tokens,
					model_name: msg.model_name,
					backend_id: msg.backend_id
				};

				newCache.set(msg.id, newMessage);
				messages.push(newMessage);
			} else {
				// Reuse existing object to preserve identity
				newCache.set(msg.id, cached);
				messages.push(cached);
			}
		});

		// Update cache and reference
		messageCache = newCache;
		lastStreamingMessages = streamingMessages;

		// Sort messages by timestamp (oldest first) for proper chronological display
		messages.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());

		// Only log when no messages are animating to avoid spam
		const hasAnimatingMessages = streamingMessages.some((m) => m.isAnimating);
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

	// --- Context Enrichment Mode ---
	let agentMode = $state<'disabled' | 'pre_processing' | 'post_processing'>('disabled');

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
		'gemini-2.5-flash': { input: 0.3, output: 2.5 },
		'gemini-2.5-pro': { input: 1.25, output: 10.0 },
		'gemini-2.5-flash-lite-preview': { input: 0.1, output: 0.4 }
	};

	// Calculate cumulative usage from messages (backend already includes system context)
	// Exclude first messages since they're pre-written content, not AI-generated
	$effect(() => {
		let inputTokens = 0;
		let outputTokens = 0;
		let totalCost = 0;

		displayMessages.forEach((message) => {
			// Skip first messages (character greetings) - they shouldn't count toward usage
			const isFirstMessage =
				message.id.startsWith('first-message-') ||
				(message.message_type === 'Assistant' && message.content === character?.first_mes);

			if (!isFirstMessage) {
				const messageInputTokens = message.prompt_tokens || 0;
				const messageOutputTokens = message.completion_tokens || 0;

				if (messageInputTokens > 0 || messageOutputTokens > 0) {
					inputTokens += messageInputTokens;
					outputTokens += messageOutputTokens;

					// Calculate cost using the model used for THIS specific message
					const messageModel = message.model_name || chat?.model_name || 'gemini-2.5-pro';
					const pricing = modelPricing[messageModel as keyof typeof modelPricing] || {
						input: 1.25,
						output: 10.0
					};

					const messageCost =
						(messageInputTokens / 1_000_000) * pricing.input +
						(messageOutputTokens / 1_000_000) * pricing.output;
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
		if (!strategy) return 'Send a message...';
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

	// --- Load Agent Mode from Chat Settings ---
	async function loadAgentMode() {
		if (!chat?.id) return;
		try {
			const result = await apiClient.getChatSessionSettings(chat.id);
			if (result.isOk()) {
				agentMode = (result.value.agent_mode as typeof agentMode) || 'disabled';
			} else {
				console.error('Failed to load agent mode:', result.error);
			}
		} catch (error) {
			console.error('Failed to load agent mode:', error);
		}
	}

	// --- Save Agent Mode to Chat Settings ---
	async function saveAgentMode(mode: typeof agentMode) {
		if (!chat?.id) return;
		try {
			const result = await apiClient.updateChatSessionSettings(chat.id, {
				agent_mode: mode
			});
			if (result.isOk()) {
				agentMode = mode;
			} else {
				console.error('Failed to save agent mode:', result.error);
				toast.error('Failed to save context enrichment mode');
			}
		} catch (error) {
			console.error('Failed to save agent mode:', error);
			toast.error('Failed to save context enrichment mode');
		}
	}

	// Load personas when component mounts (regardless of chat)
	$effect(() => {
		loadAvailablePersonas();
	});

	// Load agent mode when chat changes
	$effect(() => {
		if (chat?.id) {
			loadAgentMode();
		}
	});

	// --- Token Counting Effect ---
	let tokenCountTimeout: NodeJS.Timeout | null = null;

	$effect(() => {
		// Clear existing timeout
		if (tokenCountTimeout) {
			clearTimeout(tokenCountTimeout);
		}

		if (chatInput.trim().length > 0) {
			// Increased debounce to 3 seconds to prevent rate limiting
			tokenCountTimeout = setTimeout(async () => {
				try {
					const model = await getCurrentChatModel();
					const result = await tokenCounter.countTokensSimple(
						chatInput.trim(),
						model || undefined,
						false
					);
					// Only show if we actually got a meaningful result
					showTokenUsage = !!(result && result.total > 0);
				} catch (error) {
					console.error('Token counting failed:', error);
					showTokenUsage = false;
				}
			}, 3000); // 3 second debounce to prevent rate limiting
		} else {
			tokenCounter.reset();
			showTokenUsage = false;
		}

		// Cleanup function to clear timeout on unmount or when effect reruns
		return () => {
			if (tokenCountTimeout) {
				clearTimeout(tokenCountTimeout);
			}
		};
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
					const cost =
						(tokenUsage.input_tokens / 1_000_000) * flashPricing.input +
						(tokenUsage.output_tokens / 1_000_000) * flashPricing.output;

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
				if (
					error.message.includes('PropertyNotFound("/content/parts")') ||
					error.message.includes('PropertyNotFound("/candidates")')
				) {
					cleanErrorMessage =
						'AI safety filters blocked the suggestion request. Try again or continue chatting.';
				} else if (
					error.message.includes('Failed to parse stream data') ||
					error.message.includes('trailing characters')
				) {
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
			if (
				cleanErrorMessage.includes('PropertyNotFound("/content/parts")') ||
				cleanErrorMessage.includes('PropertyNotFound("/candidates")')
			) {
				cleanErrorMessage =
					'AI safety filters blocked the suggestion request. Try again or continue chatting.';
			} else if (
				cleanErrorMessage.includes('Failed to parse stream data') ||
				cleanErrorMessage.includes('trailing characters')
			) {
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

	// Check if this is the first user message in the chat
	function isFirstUserMessage(): boolean {
		// Check if there are any user messages in the current messages
		const hasUserMessage = streamingService.messages.some((msg) => msg.sender === 'user');
		return !hasUserMessage;
	}

	// Handle chronicle opt-in choice
	function handleChronicleChoice(enableChronicle: boolean, rememberChoice: boolean) {
		if (rememberChoice && browser) {
			localStorage.setItem('chroniclePreference', String(enableChronicle));
			chroniclePreference = enableChronicle;
		}

		showChronicleOptIn = false;

		if (enableChronicle && chat?.id) {
			// Create chronicle and associate with chat
			createChronicleForChat();
		}

		// Send the pending message
		if (pendingMessage) {
			const message = pendingMessage;
			pendingMessage = null;
			sendMessageInternal(message);
		}
	}

	// Create chronicle and associate with current chat
	async function createChronicleForChat() {
		if (!chat?.id) return;

		try {
			// Generate an AI-powered chronicle name
			let chronicleName = chat.title || 'New Chronicle';

			try {
				console.log('Generating AI chronicle name for chat:', chat.id);
				const nameResult = await apiClient.generateChronicleName(chat.id);

				if (nameResult.isOk()) {
					chronicleName = nameResult.value.name;
					console.log('Generated chronicle name:', chronicleName);
				} else {
					console.warn('Failed to generate AI chronicle name, using fallback:', nameResult.error);
					// Continue with fallback name
				}
			} catch (error) {
				console.warn('Error generating AI chronicle name, using fallback:', error);
				// Continue with fallback name
			}

			// Create a new chronicle with the generated/fallback name
			const chronicleResult = await apiClient.createChronicle({
				name: chronicleName,
				description: `Chronicle for ${chat.title || 'chat session'}`
			});

			if (chronicleResult.isOk()) {
				const chronicle = chronicleResult.value;

				// Update chat to associate with the chronicle
				const updateResult = await apiClient.updateChatSessionSettings(chat.id, {
					chronicle_id: chronicle.id
				});

				if (updateResult.isOk()) {
					// Update local chat object
					chat.player_chronicle_id = chronicle.id;
					toast.success(`Chronicle "${chronicleName}" created and linked to chat`);
				} else {
					console.error('Failed to link chronicle to chat:', updateResult.error);
					toast.error('Failed to link chronicle to chat');
				}
			} else {
				console.error('Failed to create chronicle:', chronicleResult.error);
				toast.error('Failed to create chronicle');
			}
		} catch (error) {
			console.error('Error creating chronicle:', error);
			toast.error('An error occurred while creating chronicle');
		}
	}

	async function sendMessage(content: string) {
		// DEBUG: Add stack trace to identify unwanted calls
		console.log('🚨🚨🚨 SENDMESSAGE START - content:', content.slice(0, 50) + '...');
		console.log('🚨 sendMessage called with content:', content.slice(0, 50) + '...');
		console.log('🚨 sendMessage STACK TRACE:', new Error().stack);

		dynamicSuggestedActions = []; // Clear suggestions when a message (including a suggestion) is sent

		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Check if we need to show chronicle opt-in
		// Show if: no chronicle, first user message, and no saved preference
		if (!chat.player_chronicle_id && isFirstUserMessage() && chroniclePreference === null) {
			pendingMessage = content;
			showChronicleOptIn = true;
			return;
		}

		// If user has a saved preference and no chronicle, handle it automatically
		if (!chat.player_chronicle_id && isFirstUserMessage() && chroniclePreference === true) {
			await createChronicleForChat();
		}

		sendMessageInternal(content);
	}

	async function sendMessageInternal(content: string) {
		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Build history from the single source of truth (NEW: use isAnimating instead of loading)
		const existingHistoryForApi = (streamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false)) // Only include completed messages
			.map((m) => ({
				role: m.sender,
				content: m.content // Use full content for API, not displayedContent
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
				model: currentModel || undefined,
				agentMode: agentMode
			});
			console.log(`✅ StreamingService.connect() completed at ${Date.now()}`);
		} catch (error) {
			console.error('❌ Failed to send message:', error);
			toast.error('Failed to send message. Please try again.');
		}
	}

	// Generate AI response based on current messages (used for edited messages)
	async function generateAIResponse() {
		// DEBUG: Add stack trace to identify unwanted calls
		console.log('🚨 generateAIResponse called');
		console.log('🚨 generateAIResponse STACK TRACE:', new Error().stack);

		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Build history from current messages (NEW: use isAnimating instead of loading)
		const historyToSend = (streamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false)) // Only include completed messages
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		try {
			// Use StreamingService - it will handle the last user message from history
			const lastUserMessage = historyToSend.filter((h) => h.role === 'user').pop();
			if (!lastUserMessage) {
				toast.error('No user message found to generate response.');
				return;
			}

			const currentModel = await getCurrentChatModel();
			await streamingService.connect({
				chatId: chat.id,
				userMessage: lastUserMessage.content,
				history: historyToSend.slice(0, -1), // Exclude the last user message since it's passed separately
				model: currentModel || undefined,
				agentMode: agentMode
			});
		} catch (error) {
			console.error('Failed to generate AI response:', error);
			toast.error('Failed to generate response. Please try again.');
		}
	}

	function stopGeneration() {
		streamingService.interrupt();
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
		// DEBUG: Add stack trace to identify unwanted calls
		console.log('🚨 regenerateResponse called for message:', _originalMessageId);
		console.log('🚨 regenerateResponse STACK TRACE:', new Error().stack);

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
		// Just convert to API format (NEW: use isAnimating instead of loading)
		const historyToSend = (streamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false)) // Only include completed messages
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		// Find the last user message to regenerate response for
		const lastUserMessage = historyToSend.filter((h) => h.role === 'user').pop();
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
				model: currentModel || undefined,
				agentMode: agentMode
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
		// DEBUG: Add stack trace to identify unwanted calls
		console.log('🚨 handleRetryMessage called for:', messageId);
		console.log('🚨 handleRetryMessage STACK TRACE:', new Error().stack);

		if (!chat?.id || isLoading) return;

		console.log('Retry message:', messageId);

		// Find the assistant message to retry
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
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
		// DEBUG: Add stack trace to identify unwanted calls
		console.log(
			'🚨 handleSaveEditedMessage called for:',
			messageId,
			'content:',
			newContent.slice(0, 50) + '...'
		);
		console.log('🚨 handleSaveEditedMessage STACK TRACE:', new Error().stack);

		console.log('Save edited message:', messageId, 'New content:', newContent);

		if (!chat?.id || isLoading) return;

		// Find the message index
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
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
		// DEBUG: Add stack trace to identify unwanted calls
		console.log('🚨 handleNextVariant called for:', messageId);
		console.log('🚨 handleNextVariant STACK TRACE:', new Error().stack);

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
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const failedMessage = (streamingService.messages as StreamingMessage[])[messageIndex];
		if (failedMessage.sender !== 'assistant' || !failedMessage.error) return;

		// Find the previous user message to regenerate from
		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = (streamingService.messages as StreamingMessage[])[userMessageIndex];
		if (userMessage.sender !== 'user') return;

		// Clear the error state and set to animating (NEW: use isAnimating instead of loading)
		const allMessages = [...(streamingService.messages as StreamingMessage[])];
		allMessages[messageIndex] = {
			...allMessages[messageIndex],
			isAnimating: true,
			error: undefined,
			retryable: false,
			content: '',
			displayedContent: '' // Reset displayed content for animation
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
		const messageIndex = (streamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
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
	{#key displayMessages.length}
		{console.log('🎯 About to render Messages component:', {
			displayMessagesCount: displayMessages.length,
			isLoadingMore,
			hasMoreMessages,
			firstDisplayMessage: displayMessages[0]?.id,
			lastDisplayMessage: displayMessages[displayMessages.length - 1]?.id
		})}
	{/key}

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
		onLoadMore={loadMoreMessages}
		{isLoadingMore}
		{hasMoreMessages}
		{suppressAutoScroll}
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
				<div
					class="rounded-md border border-red-200 bg-red-50 p-3 dark:border-red-800 dark:bg-red-950/20"
				>
					<div class="flex items-start gap-3">
						<div class="mt-0.5 flex-shrink-0 text-red-500">
							<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
								<path
									fill-rule="evenodd"
									d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z"
									clip-rule="evenodd"
								/>
							</svg>
						</div>
						<div class="flex-1">
							<p class="text-sm font-medium text-red-700 dark:text-red-300">
								Failed to load suggestions
							</p>
							<p class="mt-1 text-sm text-red-600 dark:text-red-400">
								{suggestionsError}
							</p>
							{#if suggestionsRetryable}
								<div class="mt-3 flex gap-2">
									<button
										type="button"
										onclick={() => {
											suggestionsError = null;
											suggestionsRetryable = false;
											fetchSuggestedActions();
										}}
										class="inline-flex items-center gap-1.5 rounded-md border border-red-300 bg-red-100 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-1 dark:border-red-700 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-950/50"
									>
										<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
											/>
										</svg>
										Retry
									</button>
									<button
										type="button"
										onclick={() => {
											suggestionsError = null;
											suggestionsRetryable = false;
										}}
										class="inline-flex items-center gap-1.5 rounded-md border border-gray-300 bg-gray-100 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-1 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
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
					console.log('🚨🚨🚨 FORM ONSUBMIT TRIGGERED');
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
						{agentMode}
						onAgentModeChange={saveAgentMode}
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
						{@const formatSessionCost = (cost: number) =>
							cost < 0.0001 ? '<$0.0001' : `$${cost.toFixed(4)}`}

						<div class="mt-2 space-y-1 border-t pt-2 text-xs text-muted-foreground">
							<!-- Main breakdown -->
							<div class="flex items-center justify-between">
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
									<span class="font-mono font-medium text-amber-600 dark:text-amber-400">
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

<!-- Chronicle Opt-in Dialog -->
<ChronicleOptInDialog bind:open={showChronicleOptIn} onConfirm={handleChronicleChoice} />
