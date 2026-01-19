<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { apiClient as _apiClient } from '$lib/api';
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import { tick, untrack } from 'svelte';
	import ChatHeader from './chat-header.svelte';
	import type { User, ScribeCharacter, Message } from '$lib/types.ts';
	import type { ScribeChatSession, ScribeChatMessage, ChatMode as _ChatMode } from '$lib/types';
	import type { UserPersona } from '$lib/types';
	import { createChatModeStrategy } from '$lib/strategies/chat';
	import Messages from './messages.svelte';
	import MultimodalInput from './multimodal-input.svelte';
	import SuggestedActions from './suggested-actions.svelte';
	import ChatConfigSidebar from './chat-config-sidebar.svelte';
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import TokenUsageDisplay from './token-usage-display.svelte';
	import { useTokenCounter } from '$lib/hooks/token-counter.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { streamingService, type StreamingMessage } from '$lib/services/StreamingService.svelte';
	import { desktopStreamingService } from '$lib/services/DesktopStreamingService.svelte';
	import { isInDesktopMode } from '$lib/api/desktop-auth';
	import ChronicleOptInDialog from './chronicle-opt-in-dialog.svelte';
	import RegenerationModal, { type AnalysisMode } from './messages/regeneration-modal.svelte';
	import { browser as _browser } from '$app/environment';
	import { getCurrentUser, getIsAuthReady, getIsAuthenticated } from '$lib/auth.svelte';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { UpgradePrompt } from './membership';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import LorebookExtractionDialog from './LorebookExtractionDialog.svelte';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import type { LorebookEntry } from '$lib/types';
	import { extractMessageContent } from '$lib/utils/message-helpers';

	// Get reactive state from streaming service
	// By directly accessing the $state properties of the service, we ensure reactivity.
	// const streamingState = $derived(activeStreamingService.getState());

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
	const _selectedPersonaStore = SelectedPersonaStore.fromContext();
	const _settingsStore = SettingsStore.fromContext();

	// State variables - use props directly for reactivity
	// Note: In Svelte 5, props are already reactive, so we can use them directly

	const chatHistory = ChatHistory.fromContext();

	// Track first message variant selection for improved caching
	let firstMessageVariantIndex = $state<number>(0);

	// Pagination state
	let nextCursor = $state<string | null>(untrack(() => initialCursor) || null);
	let isLoadingMore = $state(false);
	let hasMoreMessages = $state(untrack(() => initialCursor) !== null);
	let loadedMessagesBatches = $state<ScribeChatMessage[][]>([untrack(() => initialMessages)]);
	let suppressAutoScroll = $state(false);

	// Chronicle opt-in state
	let showChronicleOptIn = $state(false);
	let pendingMessage = $state<string | null>(null);
	let chroniclePreference: boolean | null = $state(null);
	let hasExplicitChronicleChoice = $state(false); // Track if user made explicit choice for this session

	// Regeneration modal state
	let showRegenerationModal = $state(false);
	let pendingRegenerationData = $state<{
		userMessage: string;
		messageId?: string;
		targetMessageIndex?: number;
		allMessages?: StreamingMessage[];
	} | null>(null);

	// Upgrade prompt modal state
	let showUpgradePrompt = $state(false);

	// Lorebook extraction state
	let showExtractDialog = $state(false);
	let availableLorebooks = $state<Array<{ id: string; name: string }>>([]);

	// Get the appropriate streaming service (desktop or web)
	const activeStreamingService = $derived(
		isInDesktopMode() ? desktopStreamingService : streamingService
	);

	// Load typing speed from user settings and sync with StreamingService
	$effect(() => {
		_settingsStore.loadTypingSpeed();
		// TODO: Animation speed will be handled in TypewriterMessage component
	});

	// Load saved chronicle preference from localStorage
	$effect(() => {
		if (_browser) {
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
			_selectedPersonaStore.clear();
			// Reset explicit choice flag when switching to a new chat
			hasExplicitChronicleChoice = false;
		}
	});

	// --- Scribe Chat State Management ---
	// The StreamingService is now the single source of truth for messages.
	// This component will populate the service with initial messages on load,
	// and derive its display messages directly from the service's state.

	// Message variants are now handled by the backend and included in message metadata

	// This single effect handles both populating messages for the current chat
	// and cleaning them up when the chat changes or the component is destroyed.
	let previousChatId = $state<string | null>(null);

	// Load the saved greeting variant index when chat ID becomes available
	$effect(() => {
		if (typeof window !== 'undefined' && chat?.id) {
			const saved = localStorage.getItem(`greeting-variant-${chat.id}`);
			if (saved) {
				const variantIndex = parseInt(saved, 10);
				if (!isNaN(variantIndex) && variantIndex !== firstMessageVariantIndex) {
					console.log(`🎭 Loading saved greeting variant ${variantIndex} for chat ${chat.id}`);
					firstMessageVariantIndex = variantIndex;
				}
			}
		}
	});

	$effect(() => {
		const currentChatId = chat?.id;

		// Only react to chat ID changes, not batch count changes
		if (currentChatId !== previousChatId && (currentChatId || previousChatId)) {
			// Clear messages for previous chat if switching chats
			if (previousChatId && currentChatId !== previousChatId) {
				activeStreamingService.clearMessages();

				// Reset pagination state when switching chats
				loadedMessagesBatches = [initialMessages];
				nextCursor = initialCursor || null;
				hasMoreMessages = initialCursor !== null;
				isLoadingMore = false;
			}

			if (currentChatId) {
				let newInitialMessages: StreamingMessage[];

				if (initialMessages.length === 0 && character) {
					// Determine which greeting to use based on the selected variant
					let greetingContent = character.first_mes;

					console.log(
						`🎭 Creating initial message with variant index ${firstMessageVariantIndex}`,
						{
							chatId: currentChatId,
							hasAlternateGreetings: !!character.alternate_greetings,
							alternateGreetingsCount: character.alternate_greetings?.length || 0,
							firstMessageVariantIndex
						}
					);

					if (firstMessageVariantIndex > 0 && character.alternate_greetings) {
						const altIndex = firstMessageVariantIndex - 1;
						if (
							altIndex < character.alternate_greetings.length &&
							character.alternate_greetings[altIndex]
						) {
							greetingContent = character.alternate_greetings[altIndex];
							console.log(
								`🎭 Using alternate greeting ${firstMessageVariantIndex} (index ${altIndex})`,
								{
									greetingPreview: greetingContent.slice(0, 100) + '...'
								}
							);
						} else {
							console.log(
								`🎭 Alternate greeting ${firstMessageVariantIndex} not found, using default`
							);
						}
					} else {
						console.log(`🎭 Using default greeting (first_mes)`, {
							greetingPreview: greetingContent?.slice(0, 100) + '...'
						});
					}

					if (greetingContent) {
						const firstMessageId = `first-message-${currentChatId}`;
						newInitialMessages = [
							{
								id: firstMessageId,
								sender: 'assistant',
								content: greetingContent,
								displayedContent: greetingContent, // Show immediately for initial message
								created_at: chat.created_at ?? new Date().toISOString(),
								isAnimating: false, // Initial messages don't animate
								current_variant_index: firstMessageVariantIndex,
								contentVersion: 0 // Initialize for Svelte 5 reactivity
							}
						];
					} else {
						newInitialMessages = [];
					}
				} else {
					// Flatten all loaded batches into a single array
					const allLoadedMessages = untrack(() => loadedMessagesBatches.flat());

					console.log('🔄 Processing initial messages for chat:', {
						currentChatId,
						totalMessages: allLoadedMessages.length,
						batchCount: untrack(() => loadedMessagesBatches.length)
					});

					// Log details of each message to identify duplicates
					allLoadedMessages.forEach((msg, idx) => {
						console.log(
							`📋 Initial Message ${idx}: id=${msg.id}, type=${msg.message_type}, variant_count=${msg.variant_count}, current_variant_index=${msg.current_variant_index}`
						);
					});

					newInitialMessages = allLoadedMessages.map(
						(msg) =>
							({
								id: msg.id,
								sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
								content: msg.content,
								displayedContent: msg.content, // Show immediately for existing messages
								created_at: msg.created_at ?? new Date().toISOString(),
								isAnimating: false, // Existing messages don't animate
								shouldAnimate: msg.shouldAnimate ?? false, // Carry over shouldAnimate flag
								error: msg.error,
								retryable: msg.retryable,
								prompt_tokens: msg.prompt_tokens,
								completion_tokens: msg.completion_tokens,
								model_name: msg.model_name,
								backend_id: msg.backend_id,
								status: msg.status,
								superseded_at: msg.superseded_at,
								variant_count: msg.variant_count,
								current_variant_index: msg.current_variant_index,
								is_variant: msg.is_variant,
								parent_message_id: msg.parent_message_id,
								contentVersion: 0 // Initialize for Svelte 5 reactivity
							}) as StreamingMessage
					);
				}
				// Clear and populate messages to ensure reactivity
				activeStreamingService.clearMessages();
				for (const message of newInitialMessages) {
					activeStreamingService.messages.push(message);
				}

				// Apply saved variant selection to the first assistant message (if it's a character greeting)
				if (character && newInitialMessages.length > 0) {
					const firstAssistantMessage = newInitialMessages.find(
						(msg) => msg.sender === 'assistant'
					);
					if (firstAssistantMessage && typeof window !== 'undefined') {
						const savedVariant = localStorage.getItem(`greeting-variant-${currentChatId}`);
						if (savedVariant) {
							const variantIndex = parseInt(savedVariant, 10);
							console.log(
								`🎭 Found saved variant ${variantIndex} for chat ${currentChatId}, applying to loaded message`
							);

							// Determine the correct greeting content
							let greetingContent = character.first_mes;
							if (variantIndex > 0 && character.alternate_greetings) {
								const altIndex = variantIndex - 1;
								if (
									altIndex < character.alternate_greetings.length &&
									character.alternate_greetings[altIndex]
								) {
									greetingContent = character.alternate_greetings[altIndex];
									console.log(`🎭 Applying alternate greeting ${variantIndex} to loaded message`, {
										greetingPreview: greetingContent.slice(0, 100) + '...'
									});
								}
							}

							// Update the message content and variant index
							const messageIndex = activeStreamingService.messages.findIndex(
								(msg) => msg.id === firstAssistantMessage.id
							);
							if (messageIndex !== -1) {
								activeStreamingService.messages[messageIndex] = {
									...activeStreamingService.messages[messageIndex],
									content: greetingContent || '',
									displayedContent: greetingContent || '',
									current_variant_index: variantIndex
								};
								firstMessageVariantIndex = variantIndex;
								console.log(`🎭 Updated loaded message with variant ${variantIndex} content`);
							}
						}
					}
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
				activeStreamingService.clearMessages();
			}
		};
	});

	// Sync loading state with StreamingService
	// Include both SSE connection phase AND local animation phase
	let isLoading = $derived(
		activeStreamingService.connectionStatus === 'connecting' ||
			activeStreamingService.connectionStatus === 'open' ||
			activeStreamingService.messages.some((msg) => msg.isAnimating === true)
	);

	// Load more messages function for infinite scroll
	async function loadMoreMessages() {
		if (!chat?.id || isLoadingMore || !hasMoreMessages || !nextCursor) {
			return;
		}

		isLoadingMore = true;
		suppressAutoScroll = true;

		try {
			const result = await _apiClient.getMessagesByChatId(chat.id, {
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
					currentStreamingCount: activeStreamingService.messages.length
				});

				// Log detailed message info to identify duplicates
				newMessages.forEach((msg: Message, idx: number) => {
					console.log(
						`📋 Message ${idx}: id=${msg.id}, type=${msg.message_type}, variant_count=${msg.variant_count}, current_variant_index=${msg.current_variant_index}`
					);
				});

				// Convert to ScribeChatMessage format
				const convertedMessages: ScribeChatMessage[] = newMessages.map(
					(rawMsg: Message): ScribeChatMessage => ({
						id: rawMsg.id,
						backend_id: rawMsg.id,
						session_id: rawMsg.session_id,
						message_type: rawMsg.message_type,
						content: extractMessageContent(rawMsg),
						created_at:
							typeof rawMsg.created_at === 'string'
								? rawMsg.created_at
								: rawMsg.created_at.toISOString(),
						user_id: '',
						loading: false,
						shouldAnimate: false, // Historical messages should not animate
						raw_prompt: rawMsg.raw_prompt,
						prompt_tokens: rawMsg.prompt_tokens,
						completion_tokens: rawMsg.completion_tokens,
						model_name: rawMsg.model_name,
						status: rawMsg.status,
						superseded_at: rawMsg.superseded_at,
						// Variant metadata
						variant_count: rawMsg.variant_count,
						current_variant_index: rawMsg.current_variant_index,
						is_variant: rawMsg.is_variant,
						parent_message_id: rawMsg.parent_message_id
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

					// Convert to StreamingMessage format
					const streamingMessages = convertedMessages.map(
						(msg): StreamingMessage => ({
							id: msg.id,
							sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
							content: msg.content,
							displayedContent: msg.content,
							created_at: msg.created_at || new Date().toISOString(),
							isAnimating: false,
							shouldAnimate: msg.shouldAnimate ?? false, // Carry over shouldAnimate flag
							error: msg.error || undefined,
							retryable: msg.retryable,
							prompt_tokens: msg.prompt_tokens || undefined,
							completion_tokens: msg.completion_tokens || undefined,
							model_name: msg.model_name,
							backend_id: msg.backend_id,
							status: msg.status,
							superseded_at: msg.superseded_at,
							// Variant metadata
							variant_count: msg.variant_count,
							current_variant_index: msg.current_variant_index,
							is_variant: msg.is_variant,
							parent_message_id: msg.parent_message_id,
							contentVersion: 0 // Initialize for Svelte 5 reactivity
						})
					);

					// Deduplication Logic: Check both ID and backend_id
					const existingIds = new Set(activeStreamingService.messages.map((m) => m.id));
					const existingBackendIds = new Set(
						activeStreamingService.messages
							.map((m) => m.backend_id)
							.filter((id): id is string => !!id)
					);

					const uniqueNewMessages = streamingMessages.filter((msg) => {
						const idExists = existingIds.has(msg.id);
						const backendIdExists = msg.backend_id && existingBackendIds.has(msg.backend_id);
						return !idExists && !backendIdExists;
					});

					// Handle "Empty Batch" Case (all messages were duplicates)
					if (uniqueNewMessages.length === 0) {
						console.log('⚠️ [loadMoreMessages] No new messages found after deduplication.');

						// If we have more messages on the server but this batch was all duplicates,
						// we MUST try the next batch immediately to avoid getting stuck.
						if (hasMoreMessages) {
							console.log('🔄 [loadMoreMessages] Automatically fetching next batch...');
							// Release the lock briefly to allow the recursive call to proceed
							isLoadingMore = false;
							// We need to pass a retry count, but since we can't easily change the function signature
							// without affecting the template, we'll just call it again.
							// Ideally we should add a retryCount param to loadMoreMessages.
							// For now, let's just return and let the user scroll again or rely on the infinite scroll
							// to trigger again if we're still at the top?
							// Actually, infinite scroll might not trigger if the content height didn't change.
							// So explicit recursion is better.
							await loadMoreMessages();
							return;
						}

						suppressAutoScroll = false;
						return;
					}

					console.log(
						`✅ [loadMoreMessages] Prepending ${uniqueNewMessages.length} unique messages`
					);

					// Prepend the new messages to the beginning of the array (create new array reference)
					activeStreamingService.messages = [
						...uniqueNewMessages,
						...activeStreamingService.messages
					];

					console.log('✅ Added messages to streaming service:', {
						addedCount: uniqueNewMessages.length,
						newTotalCount: activeStreamingService.messages.length,
						firstNewMessage: uniqueNewMessages[0]?.id,
						lastNewMessage: uniqueNewMessages[uniqueNewMessages.length - 1]?.id
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
							created_at: msg.created_at || new Date().toISOString(),
							isAnimating: false,
							error: msg.error || undefined,
							retryable: msg.retryable,
							prompt_tokens: msg.prompt_tokens || undefined,
							completion_tokens: msg.completion_tokens || undefined,
							model_name: msg.model_name,
							backend_id: msg.backend_id,
							status: msg.status,
							superseded_at: msg.superseded_at,
							// Variant metadata
							variant_count: msg.variant_count,
							current_variant_index: msg.current_variant_index,
							is_variant: msg.is_variant,
							parent_message_id: msg.parent_message_id,
							contentVersion: 0 // Initialize for Svelte 5 reactivity
						})
					);

					activeStreamingService.messages = [
						...streamingMessages,
						...activeStreamingService.messages
					];
					loadedMessagesBatches.push(convertedMessages);
				}

				// Update cursor and hasMore state
				nextCursor = newCursor;
				hasMoreMessages = newCursor !== null;
			}
		} catch (_error) {
			console.error('Error loading more messages:', _error);
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
	// 	if (activeStreamingService.connectionStatus === 'closed') {
	// 		console.log('✅ StreamingService connection completed (status: closed) - REFRESH DISABLED');
	// 		// DISABLED: Force a re-render by updating the displayMessages derivation
	// 		// The messages should already have loading: false set by finalizeMessage
	// 		console.log('Current messages loading states:', activeStreamingService.messages.map(m => ({ id: m.id, loading: m.loading })));
	// 	}
	// });

	// Object identity cache to prevent unnecessary component recreation
	let messageCache = new Map<string, ScribeChatMessage>();
	let lastStreamingMessages: unknown[] = [];

	// Create a single, reactive source of truth for display messages with object identity preservation
	let displayMessages = $derived.by(() => {
		try {
			const streamingMessages = activeStreamingService.messages;
			// Derived displayMessages calculation

			// Check if messages array actually changed to avoid unnecessary work
			// Use both reference equality and length check for robustness
			if (
				streamingMessages === lastStreamingMessages ||
				(Array.isArray(lastStreamingMessages) &&
					streamingMessages.length === lastStreamingMessages.length &&
					streamingMessages.every((msg, idx) => msg === lastStreamingMessages[idx]))
			) {
				// Using cached result - no change detected
				return Array.from(messageCache.values());
			}

			// Processing new messages array

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
					cached.contentVersion !== msg.contentVersion || // CRITICAL: Detect streaming content updates
					cached.prompt_tokens !== msg.prompt_tokens ||
					cached.completion_tokens !== msg.completion_tokens ||
					cached.error !== msg.error ||
					cached.variant_count !== msg.variant_count ||
					cached.current_variant_index !== msg.current_variant_index;

				if (hasChanged) {
					// Message content changed

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
						backend_id: msg.backend_id,
						// CRITICAL: Preserve contentVersion for Svelte 5 fine-grained reactivity
						contentVersion: msg.contentVersion,
						// Include variant metadata for proper UI display
						variant_count: msg.variant_count,
						current_variant_index: msg.current_variant_index,
						is_variant: msg.is_variant,
						parent_message_id: msg.parent_message_id,
						// Include regeneration flag for loading indicator
						isRegenerating: msg.isRegenerating,
						// Preserve shouldAnimate flag for animation control
						shouldAnimate: msg.shouldAnimate
						// Note: _variantChangedAt removed due to type conflicts
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
			messages.sort((a, b) => {
				const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
				const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;
				return aTime - bTime;
			});

			// Only log when no messages are animating to avoid spam
			const _hasAnimatingMessages = streamingMessages.some((m) => m.isAnimating);
			return messages;
		} catch (_error) {
			console.error('❌ Error in displayMessages derived:', _error);
			// Return cached messages if available, otherwise return empty array
			return Array.from(messageCache.values());
		}
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

	// Track suggested actions token usage (separate from main session tracking)
	// Prefixed with _ as it's set but not currently displayed (kept for potential future use)
	let _suggestedActionsTokens = $state({
		input: 0,
		output: 0,
		total: 0,
		cost: 0
	});

	// Pricing per model (per 1M tokens)
	// Model pricing with 20% markup (used for suggested actions cost estimation only)
	// Main chat session costs come from server-side credit tracking (chat.total_credits_used)
	const modelPricing = {
		'gemini-2.5-flash': { input: 0.36, output: 3.0 }, // 20% markup on $0.30/$2.50
		'gemini-2.5-flash-preview-09-2025': { input: 0.36, output: 3.0 }, // Same as flash
		'gemini-2.5-flash-image': { input: 0.36, output: 3.0 }, // Same as flash
		'gemini-2.5-pro': { input: 1.5, output: 12.0 }, // 20% markup on $1.25/$10.00
		'gemini-2.5-flash-lite-preview-09-2025': { input: 0.12, output: 0.48 } // 20% markup on $0.10/$0.40
	};
	let availablePersonas = $state<UserPersona[]>([]);

	// User persona for template substitution
	let currentUserPersona = $state<UserPersona | null>(null);
	let userPersonaName = $derived(currentUserPersona?.name || 'User');

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
		} catch (_error) {
			console.error('Failed to create chat mode strategy:', _error, 'for mode:', chat.chat_mode);
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
			const result = await _apiClient.getUserPersonas();
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
		} catch (_error) {
			console.error('Failed to load personas:', _error);
			toast.error('Failed to load personas');
		}
	}

	async function loadUserPersona() {
		console.log('🔍 loadUserPersona: Starting persona load');
		try {
			const currentUser = getCurrentUser();
			console.log('🔍 loadUserPersona: currentUser =', currentUser);

			if (currentUser?.default_persona_id) {
				console.log(
					'🔍 loadUserPersona: Fetching persona with ID:',
					currentUser.default_persona_id
				);
				const personaResult = await _apiClient.getUserPersona(currentUser.default_persona_id);
				if (personaResult.isOk()) {
					currentUserPersona = personaResult.value;
					console.log('✅ loadUserPersona: Successfully loaded persona:', currentUserPersona);
				} else {
					console.warn('⚠️ loadUserPersona: Failed to load user persona:', personaResult.error);
					// Create a fallback persona with username
					if (currentUser.username) {
						currentUserPersona = { name: currentUser.username } as UserPersona;
						console.log('🔄 loadUserPersona: Using username as fallback:', currentUserPersona);
					}
				}
			} else if (currentUser?.username) {
				// Create a fallback persona with username
				currentUserPersona = { name: currentUser.username } as UserPersona;
				console.log(
					'🔄 loadUserPersona: No default_persona_id, using username:',
					currentUserPersona
				);
			} else {
				console.warn('⚠️ loadUserPersona: No default_persona_id and no username available');
			}
		} catch (_error) {
			console.error('❌ loadUserPersona: Error loading user persona:', _error);
			// currentUserPersona remains null, so userPersonaName will be 'User'
		}

		console.log(
			'🔍 loadUserPersona: Completed. currentUserPersona =',
			currentUserPersona,
			', userPersonaName will be:',
			currentUserPersona?.name || 'User'
		);
	}

	// --- Get Current Chat Model ---
	async function getCurrentChatModel() {
		if (!chat?.id) return null;

		try {
			const result = await _apiClient.getChatSessionSettings(chat.id);
			if (result.isOk()) {
				return result.value.model_name || null;
			} else {
				console.error('Failed to get chat model:', result.error);
			}
		} catch (_error) {
			console.error('Failed to get chat model:', _error);
		}
		return null;
	}

	// --- Load Agent Mode from Chat Settings ---
	async function loadAgentMode() {
		if (!chat?.id) return;
		try {
			const result = await _apiClient.getChatSessionSettings(chat.id);
			if (result.isOk()) {
				agentMode = (result.value.agent_mode as typeof agentMode) || 'disabled';
			} else {
				console.error('Failed to load agent mode:', result.error);
			}
		} catch (_error) {
			console.error('Failed to load agent mode:', _error);
		}
	}

	// --- Save Agent Mode to Chat Settings ---
	async function saveAgentMode(mode: typeof agentMode) {
		if (!chat?.id) return;

		// Update local state immediately for UI responsiveness
		const previousMode = agentMode;
		agentMode = mode;

		try {
			const result = await _apiClient.updateChatSessionSettings(chat.id, {
				agent_mode: mode
			});

			if (result.isOk()) {
				// Show success feedback
				const modeLabel =
					mode === 'disabled'
						? 'Off'
						: mode === 'pre_processing'
							? 'Pre-processing'
							: 'Post-processing';
				toast.success(`Context enrichment: ${modeLabel}`);
			} else {
				// Revert on error
				agentMode = previousMode;
				console.error('Failed to save agent mode:', result.error);
				toast.error('Failed to update context enrichment mode');
			}
		} catch (_error) {
			// Revert on error
			agentMode = previousMode;
			console.error('Failed to save agent mode:', _error);
			toast.error('Failed to update context enrichment mode');
		}
	}

	// --- Refresh Chat Metadata (Token Counts and Costs) ---
	async function refreshChatMetadata() {
		if (!chat?.id) return;

		try {
			const result = await _apiClient.getChatById(chat.id);
			if (result.isOk()) {
				// Mutate specific fields directly to avoid triggering full re-render
				// In Svelte 5, direct mutation of props triggers fine-grained reactivity
				chat.total_prompt_tokens = result.value.total_prompt_tokens;
				chat.total_completion_tokens = result.value.total_completion_tokens;
				chat.total_credits_used = result.value.total_credits_used;

				console.log('✅ Refreshed chat metadata:', {
					total_prompt_tokens: chat.total_prompt_tokens,
					total_completion_tokens: chat.total_completion_tokens,
					total_credits_used: chat.total_credits_used
				});
			} else {
				console.error('Failed to refresh chat metadata:', result.error);
			}
		} catch (_error) {
			console.error('Failed to refresh chat metadata:', _error);
		}
	}

	// Function to handle token limit reached - show upgrade prompt instead of toast
	function handleTokenLimitReached() {
		if (ENABLE_PAYMENTS && subscriptionStore.isAtLimit) {
			showUpgradePrompt = true;
			return true; // Indicate that limit was reached
		}
		return false; // No limit reached
	}

	// Load personas when component mounts (regardless of chat)
	// CRITICAL: Guard with auth checks and hasFetched flag to prevent infinite loop
	let hasFetchedPersonas = $state(false);
	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		// Only fetch once when auth is ready
		if (!hasFetchedPersonas && authReady && authenticated) {
			console.log('[chat.svelte] Initial persona fetch - auth ready');
			untrack(() => {
				loadAvailablePersonas();
				loadUserPersona();
				hasFetchedPersonas = true;
			});
		}
	});

	// Load lorebooks when component mounts (for extraction dialog)
	// CRITICAL: Guard with auth checks and hasFetched flag to prevent infinite loop
	let hasFetchedLorebooks = $state(false);
	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		if (!hasFetchedLorebooks && authReady && authenticated) {
			console.log('[chat.svelte] Initial lorebooks fetch - auth ready');
			untrack(() => {
				async function loadLorebooks() {
					await lorebookStore.loadLorebooks();
					// Map lorebooks to simple format needed by dialog
					// Use the getter directly, not .state.lorebooks
					availableLorebooks = (lorebookStore.lorebooks || []).map((lb) => ({
						id: lb.id,
						name: lb.name
					}));
				}
				loadLorebooks();
				hasFetchedLorebooks = true;
			});
		}
	});

	// Load agent mode when chat changes
	$effect(() => {
		if (chat?.id) {
			loadAgentMode();
		}
	});

	// --- Token Counting Effect ---
	let tokenCountTimeout: ReturnType<typeof setTimeout> | null = null;

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
				} catch (_error) {
					console.error('Token counting failed:', _error);
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

			const result = await _apiClient.fetchSuggestedActions(chat.id);

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

					_suggestedActionsTokens = {
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
		} catch (err: unknown) {
			// Catch any unexpected errors during the API client call itself
			console.error('Error fetching suggested actions:', err);

			// Clean up error message for user display
			let cleanErrorMessage = (err as Error).message || 'An unexpected error occurred.';
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
		const userMessages = activeStreamingService.messages.filter((msg) => msg.sender === 'user');
		console.log('🔍 [isFirstUserMessage] User messages found:', userMessages.length);
		if (userMessages.length > 0) {
			console.log(
				'🔍 [isFirstUserMessage] First user message ID:',
				userMessages[0].id,
				'Content:',
				userMessages[0].content.slice(0, 20)
			);
		}
		return userMessages.length === 0;
	}

	// Template substitution for frontend preview - following character-overview.svelte pattern
	function substituteTemplateVariables(text: string, characterName: string): string {
		if (!text) return text;

		console.log('🔤 substituteTemplateVariables: Called with userPersonaName =', userPersonaName);
		console.log('🔤 Text length:', text.length, 'chars');

		// Find all {{user}} instances and log their context
		const userTemplateRegex = /\{\{user\}\}/g;
		let match;
		let matchCount = 0;
		while ((match = userTemplateRegex.exec(text)) !== null) {
			matchCount++;
			const start = Math.max(0, match.index - 20);
			const end = Math.min(text.length, match.index + match[0].length + 20);
			const context = text.substring(start, end);
			console.log(
				`🔤 Found {{user}} #${matchCount} at position ${match.index}:`,
				JSON.stringify(context)
			);
		}
		console.log(`🔤 Total {{user}} templates found: ${matchCount}`);

		// Find all {{char}} instances
		const charTemplateRegex = /\{\{char\}\}/g;
		let _charMatch;
		let charMatchCount = 0;
		while ((_charMatch = charTemplateRegex.exec(text)) !== null) {
			charMatchCount++;
		}
		console.log(`🔤 Total {{char}} templates found: ${charMatchCount}`);

		// Perform replacements
		const result = text
			.replace(/\{\{char\}\}/g, characterName)
			.replace(/\{\{user\}\}/g, userPersonaName);

		// Check if any replacements actually happened
		if (result === text) {
			console.log('⚠️ substituteTemplateVariables: No replacements made!');
		} else {
			console.log(
				'✅ substituteTemplateVariables: Replacements made. Result length:',
				result.length
			);
			// Show a preview of the result
			console.log('🔤 Result preview (first 200 chars):', result.substring(0, 200));
		}

		return result;
	}

	// Handle chronicle opt-in choice
	async function handleChronicleChoice(enableChronicle: boolean, rememberChoice: boolean) {
		// Mark that user made an explicit choice for this session
		hasExplicitChronicleChoice = true;

		if (rememberChoice && _browser) {
			localStorage.setItem('chroniclePreference', String(enableChronicle));
			chroniclePreference = enableChronicle;
		}

		if (enableChronicle && chat?.id) {
			// Create chronicle and associate with chat
			await createChronicleForChat();
		}

		// Send the pending message first
		if (pendingMessage) {
			const message = pendingMessage;
			pendingMessage = null;
			sendMessageInternal(message);
		}

		// CRITICAL: Wait for next tick before closing dialog
		// This ensures streaming service state updates happen first,
		// preventing parent re-renders from resetting the dialog state
		await tick();
		showChronicleOptIn = false;
	}

	// Create chronicle and associate with current chat
	async function createChronicleForChat() {
		if (!chat?.id) return;

		try {
			// Generate an AI-powered chronicle name
			let chronicleName = chat.title || 'New Chronicle';

			try {
				console.log('Generating AI chronicle name for chat:', chat.id);
				const nameResult = await _apiClient.generateChronicleName(chat.id);

				if (nameResult.isOk()) {
					chronicleName = nameResult.value.name;
					console.log('Generated chronicle name:', chronicleName);
				} else {
					console.warn('Failed to generate AI chronicle name, using fallback:', nameResult.error);
					// Continue with fallback name
				}
			} catch (_error) {
				console.warn('Error generating AI chronicle name, using fallback:', _error);
				// Continue with fallback name
			}

			// Create a new chronicle with the generated/fallback name
			const chronicleResult = await _apiClient.createChronicle({
				name: chronicleName,
				description: `Chronicle for ${chat.title || 'chat session'}`
			});

			if (chronicleResult.isOk()) {
				const chronicle = chronicleResult.value;

				// Update chat to associate with the chronicle
				const updateResult = await _apiClient.updateChatSessionSettings(chat.id, {
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
		} catch (_error) {
			console.error('Error creating chronicle:', _error);
			toast.error('An error occurred while creating chronicle');
		}
	}

	async function sendMessage(content: string) {
		try {
			// DEBUG: Add stack trace to identify unwanted calls
			console.log(
				'🚨🚨🚨 SENDMESSAGE START - content:',
				content ? content.slice(0, 50) : 'UNDEFINED'
			);
			// console.log('🚨 sendMessage called with content:', content.slice(0, 50) + '...');
			// console.log('🚨 sendMessage STACK TRACE:', new Error().stack);

			dynamicSuggestedActions = []; // Clear suggestions when a message (including a suggestion) is sent

			// DIAGNOSTIC: Check all conditions
			console.log('🔍 [sendMessage] chat?.id:', chat?.id);
			console.log('🔍 [sendMessage] user?.id:', user?.id);

			if (!chat?.id || !user?.id) {
				console.error('❌ [sendMessage] Missing chat.id or user.id - EARLY RETURN');
				toast.error('Chat session or user information is missing.');
				return;
			}

			console.log('✅ [sendMessage] chat and user IDs present');

			// DIAGNOSTIC: Log chronicles state before checks
			console.log('🔍 [sendMessage] chat.player_chronicle_id:', chat.player_chronicle_id);
			// console.log('🔍 [sendMessage] isFirstUserMessage():', isFirstUserMessage()); // Moved down to avoid potential error
			console.log('🔍 [sendMessage] chroniclePreference:', chroniclePreference);
			console.log('🔍 [sendMessage] hasExplicitChronicleChoice:', hasExplicitChronicleChoice);

			// Check if we need to show chronicle opt-in
			// Show if: no chronicle, first user message, no saved preference, and no explicit choice made
			const _isFirst = isFirstUserMessage();
			const _userMsgCount = activeStreamingService.messages.filter(
				(msg) => msg.sender === 'user'
			).length;

			// DEBUG: Always show toast with condition values
			toast.info(
				`Debug: First=${_isFirst} (${_userMsgCount}), ChronID=${chat.player_chronicle_id}, Pref=${chroniclePreference}, Expl=${hasExplicitChronicleChoice}`
			);

			// FORCE SHOW for debugging

			/*
		if (
			!chat.player_chronicle_id &&
			_isFirst &&
			chroniclePreference === null &&
			!hasExplicitChronicleChoice
		) {
			console.log('📖 [sendMessage] SHOWING CHRONICLES OPT-IN DIALOG');
			pendingMessage = content;
			showChronicleOptIn = true;
			return;
		}
		*/

			console.log('✅ [sendMessage] Chronicles opt-in dialog check passed');

			// If user has a saved preference and no chronicle, handle it automatically
			// BUT only if they haven't made an explicit choice for this session
			if (
				!chat?.player_chronicle_id &&
				isFirstUserMessage() &&
				chroniclePreference === true &&
				!hasExplicitChronicleChoice
			) {
				console.log('📖 [sendMessage] Auto-creating chronicle based on saved preference...');
				try {
					await createChronicleForChat();
					console.log('✅ [sendMessage] Chronicle auto-created successfully');
				} catch (error) {
					console.error('❌ [sendMessage] Failed to auto-create chronicle:', error);
					// Continue anyway - don't block message sending
				}
			}

			console.log('🚀 [sendMessage] Calling sendMessageInternal()...');
			sendMessageInternal(content);
			console.log('✅ [sendMessage] sendMessageInternal() call completed');
		} catch (err) {
			console.error('🚨🚨🚨 CRITICAL ERROR IN SENDMESSAGE:', err);
			toast.error('Error sending message: ' + (err instanceof Error ? err.message : String(err)));
		}
	}

	async function sendMessageInternal(content: string) {
		console.log(
			'🚀 [sendMessageInternal] ===== ENTRY POINT ===== content:',
			content.slice(0, 50) + '...'
		);
		console.log('🔍 [sendMessageInternal] chat?.id:', chat?.id);
		console.log('🔍 [sendMessageInternal] user?.id:', user?.id);

		if (!chat?.id || !user?.id) {
			console.error('❌ [sendMessageInternal] Missing chat.id or user.id - EARLY RETURN');
			toast.error('Chat session or user information is missing.');
			return;
		}

		console.log('✅ [sendMessageInternal] chat and user IDs present');

		// Check token limits if payments are enabled
		console.log('🔍 [sendMessageInternal] Checking token limits...');
		if (handleTokenLimitReached()) {
			console.warn('⚠️ [sendMessageInternal] Token limit reached - EARLY RETURN');
			return;
		}

		console.log('✅ [sendMessageInternal] Token limit check passed');

		// Build history from the single source of truth (NEW: use isAnimating instead of loading)
		const existingHistoryForApi = (activeStreamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false)) // Only include completed messages
			.map((m) => ({
				role: m.sender,
				content: m.content // Use full content for API, not displayedContent
			}));

		// DEBUG: Log the first assistant message content to verify variant is applied
		const firstAssistantInHistory = existingHistoryForApi.find((msg) => msg.role === 'assistant');
		if (firstAssistantInHistory) {
			console.log('🎭 First assistant message being sent to backend:', {
				contentPreview: firstAssistantInHistory.content.slice(0, 150) + '...',
				fullContentLength: firstAssistantInHistory.content.length,
				currentVariantIndex: firstMessageVariantIndex
			});
		}

		try {
			// Use DesktopStreamingService for desktop, StreamingService for web
			const service = isInDesktopMode() ? desktopStreamingService : streamingService;
			const serviceName = isInDesktopMode() ? 'DesktopStreamingService' : 'StreamingService';

			const currentModel = await getCurrentChatModel();
			console.log(`🚀 Starting ${serviceName} connection:`, {
				chatId: chat.id,
				userMessage: content,
				historyLength: existingHistoryForApi.length,
				model: currentModel
			});
			await service.connect({
				chatId: chat.id,
				userMessage: content,
				history: existingHistoryForApi,
				model: currentModel || undefined,
				agentMode: agentMode
			});
			console.log(`✅ ${serviceName}.connect() completed at ${Date.now()}`);

			// Refresh chat metadata to update token counts and costs
			await refreshChatMetadata();
		} catch (_error) {
			console.error('❌ Failed to send message:', _error);

			// Check if this is a daily limit error
			if (
				_error instanceof Error &&
				(_error.name === 'DailyLimitError' ||
					_error.message.includes('Daily message limit reached'))
			) {
				// Show upgrade prompt for daily limit errors
				if (ENABLE_PAYMENTS) {
					showUpgradePrompt = true;
				} else {
					toast.error(_error.message);
				}
			} else {
				toast.error('Failed to send message. Please try again.');
			}
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

		// Check token limits if payments are enabled
		if (handleTokenLimitReached()) {
			return;
		}

		// Build history from current messages (NEW: use isAnimating instead of loading)
		const historyToSend = (activeStreamingService.messages as StreamingMessage[])
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
			await activeStreamingService.connect({
				chatId: chat.id,
				userMessage: lastUserMessage.content,
				history: historyToSend.slice(0, -1), // Exclude the last user message since it's passed separately
				model: currentModel || undefined,
				agentMode: agentMode
			});
		} catch (_error) {
			console.error('Failed to generate AI response:', _error);

			// Check if this is a daily limit error
			if (
				_error instanceof Error &&
				(_error.name === 'DailyLimitError' ||
					_error.message.includes('Daily message limit reached'))
			) {
				// Show upgrade prompt for daily limit errors
				if (ENABLE_PAYMENTS) {
					showUpgradePrompt = true;
				} else {
					toast.error(_error.message);
				}
			} else {
				toast.error('Failed to generate response. Please try again.');
			}
		}
	}

	function stopGeneration() {
		activeStreamingService.interrupt();
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
	async function regenerateResponse(
		_userMessageContent: string,
		originalMessageId?: string,
		analysisMode: AnalysisMode = 'existing',
		guidance?: string,
		targetMessageId?: string
	) {
		if (!chat?.id || !user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Check token limits if payments are enabled
		if (handleTokenLimitReached()) {
			return;
		}

		// Check if currently loading
		if (isLoading) {
			toast.warning('Please wait for the current message to complete.');
			return;
		}

		// The backend will handle variant creation when we pass variant_of parameter

		// Build the history - messages array already has the right messages after we removed the assistant message
		// Just convert to API format (NEW: use isAnimating instead of loading)
		const historyToSend = (activeStreamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false)) // Only include completed messages
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		console.log('DEBUG: regenerateResponse guidance:', guidance);

		// Find the last user message to regenerate response for
		const lastUserMessage = historyToSend.filter((h) => h.role === 'user').pop();
		if (!lastUserMessage) {
			toast.error('No user message found to regenerate response.');
			return;
		}

		try {
			// Use StreamingService for regeneration - it will handle the streaming
			const currentModel = await getCurrentChatModel();

			// Find the target message in the streaming service for variant update
			let targetMessageIdForVariant: string | undefined = targetMessageId;
			if (!targetMessageIdForVariant && originalMessageId) {
				const currentMessages = activeStreamingService.messages as StreamingMessage[];
				console.log('🔍 Searching for originalMessageId:', originalMessageId);
				console.log(
					'🔍 Current messages:',
					currentMessages.map((m) => ({ id: m.id, backend_id: m.backend_id, sender: m.sender }))
				);

				const targetMessage = currentMessages.find(
					(msg) => msg.backend_id === originalMessageId || msg.id === originalMessageId
				);
				if (targetMessage) {
					targetMessageIdForVariant = targetMessage.id; // Use frontend ID for variant update
					console.log('🎯 Found target message for variant update:', targetMessageIdForVariant);
				} else {
					console.warn('⚠️ Target message not found for variant update:', originalMessageId);
				}
			}

			if (originalMessageId) {
				console.log('🎯 Generating new variant for message:', originalMessageId);
			} else {
				console.log('🎯 Generating new response (not a variant)');
			}

			// Fix for retry bug: Only slice history if the last message isn't already a user message
			// This happens when retrying a failed message - the failed assistant message was removed,
			// so history already ends with the user message we want to regenerate from
			const lastHistoryMessage = historyToSend[historyToSend.length - 1];
			const shouldSliceHistory = lastHistoryMessage?.role !== 'user';
			const finalHistory = shouldSliceHistory ? historyToSend.slice(0, -1) : historyToSend;

			console.log('📋 History construction:', {
				historyLength: historyToSend.length,
				lastRole: lastHistoryMessage?.role,
				shouldSlice: shouldSliceHistory,
				finalHistoryLength: finalHistory.length,
				finalLastRole: finalHistory[finalHistory.length - 1]?.role
			});

			await activeStreamingService.connect({
				chatId: chat.id,
				userMessage: lastUserMessage.content,
				history: finalHistory,
				model: currentModel || undefined,
				agentMode: agentMode,
				analysisMode: analysisMode, // Pass the analysis mode for regeneration
				isRegeneration: true, // Prevent duplicate user message
				guidance: guidance, // Pass guidance for regeneration steering
				targetMessageId: targetMessageIdForVariant, // Pass target message ID for variant update
				variantOf: originalMessageId // Create response as variant of original message
			});

			// Refresh chat metadata to update token counts and costs
			await refreshChatMetadata();
			// Update chat preview after successful regeneration
			// Note: StreamingService will handle message creation and updates
			const preview = lastUserMessage.content.substring(0, 100);
			chatHistory.updateChatPreview(chat.id, preview);
		} catch (_error) {
			console.error('Failed to regenerate response:', _error);

			// Check if this is a daily limit error
			if (
				_error instanceof Error &&
				(_error.name === 'DailyLimitError' ||
					_error.message.includes('Daily message limit reached'))
			) {
				// Show upgrade prompt for daily limit errors
				if (ENABLE_PAYMENTS) {
					showUpgradePrompt = true;
				} else {
					toast.error(_error.message);
				}
			} else {
				toast.error('Failed to regenerate response. Please try again.');
			}
		}
	}

	// Handle greeting changes from alternate greetings
	async function handleGreetingChanged(detail: { index: number; content: string }) {
		const { content, index } = detail;

		console.log(`🎭 Greeting changed to variant ${index}`, {
			chatId: chat?.id,
			content: content.slice(0, 100) + '...'
		});

		// Track the selected variant index
		firstMessageVariantIndex = index;

		// Save to localStorage for persistence
		if (typeof window !== 'undefined' && chat?.id) {
			localStorage.setItem(`greeting-variant-${chat.id}`, index.toString());
			console.log(`🎭 Saved greeting variant ${index} to localStorage for chat ${chat.id}`);
		}

		// Update the first message content in the messages array with variant metadata
		const firstMessageId = `first-message-${chat?.id ?? 'initial'}`;
		const firstMessage = activeStreamingService.messages.find((msg) => msg.id === firstMessageId);

		// Optimistically update the UI
		activeStreamingService.messages = (activeStreamingService.messages as StreamingMessage[]).map(
			(msg) =>
				msg.id === firstMessageId
					? {
							...msg,
							content,
							displayedContent: content,
							current_variant_index: index,
							// Force re-render by updating a timestamp
							_variantChangedAt: Date.now()
						}
					: msg
		);

		// If this is a real backend message (has backend_id), persist the variant selection
		if (firstMessage?.backend_id) {
			try {
				console.log('🔄 Persisting first message variant selection to backend:', {
					messageId: firstMessage.backend_id,
					variantIndex: index
				});

				const result = await _apiClient.selectMessageVariant(firstMessage.backend_id, {
					variant_index: index
				});

				if (result.isOk()) {
					console.log('✅ Successfully persisted first message variant selection to backend');
				} else {
					console.warn('⚠️ Failed to persist variant selection to backend:', result.error);
					// Don't show error to user since the UI still works without backend sync
				}
			} catch (_error) {
				console.warn('⚠️ Error persisting first message variant selection:', _error);
				// Don't show error to user since this is not critical for functionality
			}
		}
	}

	// Message action handlers
	function handleRetryMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Retry message:', messageId);

		// Find the assistant message to retry
		const messageIndex = (activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const targetMessage = (activeStreamingService.messages as StreamingMessage[])[messageIndex];
		if (targetMessage.sender !== 'assistant') return;

		// Find the previous user message to regenerate from
		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = (activeStreamingService.messages as StreamingMessage[])[userMessageIndex];
		if (userMessage.sender !== 'user') return;

		// DEFER CHANGES: Only collect data for the modal, don't modify anything yet
		// Pass the backend_id if available for variant creation
		const backendMessageId = targetMessage.backend_id || messageId;

		// Store the data needed for cleanup after modal confirmation
		pendingRegenerationData = {
			userMessage: userMessage.content,
			messageId: backendMessageId,
			// Store additional data needed for cleanup
			targetMessageIndex: messageIndex,
			allMessages: [...(activeStreamingService.messages as StreamingMessage[])]
		};
		showRegenerationModal = true;
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
		const messageIndex = (activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const targetMessage = (activeStreamingService.messages as StreamingMessage[])[messageIndex];
		if (targetMessage.sender !== 'user') return;

		// Update the message content
		const allMessages = [...(activeStreamingService.messages as StreamingMessage[])];
		allMessages[messageIndex].content = newContent;

		// Get messages that will be removed for backend cleanup
		const removedMessages = allMessages.slice(messageIndex + 1);

		// Clear all subsequent messages (everything after this user message)
		activeStreamingService.messages = allMessages.slice(0, messageIndex + 1);

		// Variant data is now managed by the backend

		// Delete trailing messages from backend (including embeddings)
		if (removedMessages.length > 0 && removedMessages[0].backend_id) {
			try {
				await _apiClient.deleteTrailingMessages(removedMessages[0].backend_id);
			} catch (err) {
				console.warn('Failed to delete trailing messages from backend:', err);
				// Continue with regeneration even if cleanup fails
			}
		}

		// Generate new AI response based on the edited message
		// Don't use sendMessage since we already have the user message - just trigger AI response
		generateAIResponse();
	}

	async function handlePreviousVariant(messageId: string) {
		console.log('⬅️ Previous variant:', messageId);

		// Find the message to get current variant info (check both frontend ID and backend ID)
		const message = activeStreamingService.messages.find(
			(msg) => msg.id === messageId || msg.backend_id === messageId
		);
		if (!message || (message.current_variant_index ?? 0) <= 0) return;

		// Can't go back if we're at index 0 (original message)
		const currentIndex = message.current_variant_index ?? 0;
		const newIndex = currentIndex - 1;

		try {
			// Use backend ID for API call if available, otherwise use frontend ID
			const apiMessageId = message.backend_id || messageId;
			const result = await _apiClient.selectMessageVariant(apiMessageId, {
				variant_index: newIndex
			});

			if (result.isOk()) {
				const updatedMessage = result.value;
				// Update the message in the streaming service (match by frontend or backend ID)
				activeStreamingService.messages = (
					activeStreamingService.messages as StreamingMessage[]
				).map((msg) => {
					if (msg.id === messageId || msg.backend_id === messageId) {
						return {
							...msg,
							content: updatedMessage.content,
							current_variant_index: updatedMessage.current_variant_index,
							displayedContent: updatedMessage.content
						};
					}
					return msg;
				});
			} else {
				console.error('Failed to select previous variant:', result.error);
				toast.error('Failed to switch to previous variant');
			}
		} catch (err) {
			console.error('Failed to select previous variant:', err);
			toast.error('Failed to switch to previous variant');
		}
	}

	async function handleNextVariant(messageId: string) {
		// Find the message to get current variant info (check both frontend ID and backend ID)
		const message = activeStreamingService.messages.find(
			(msg) => msg.id === messageId || msg.backend_id === messageId
		);
		if (!message) return;

		const currentIndex = message.current_variant_index ?? 0;
		const variantCount = message.variant_count ?? 0;

		console.log(
			`➡️ Next variant: messageId=${messageId}, currentIndex=${currentIndex}, variantCount=${variantCount}`
		);

		// If we have saved variants and we're not at the latest one
		if (variantCount > 0 && currentIndex < variantCount - 1) {
			// Show next variant
			const newIndex = currentIndex + 1;

			try {
				// Use backend ID for API call if available, otherwise use frontend ID
				const apiMessageId = message.backend_id || messageId;
				const result = await _apiClient.selectMessageVariant(apiMessageId, {
					variant_index: newIndex
				});

				if (result.isOk()) {
					const updatedMessage = result.value;
					// Update the message in the streaming service (match by frontend or backend ID)
					activeStreamingService.messages = (
						activeStreamingService.messages as StreamingMessage[]
					).map((msg) => {
						if (msg.id === messageId || msg.backend_id === messageId) {
							return {
								...msg,
								content: updatedMessage.content,
								current_variant_index: updatedMessage.current_variant_index,
								displayedContent: updatedMessage.content
							};
						}
						return msg;
					});
				} else {
					console.error('Failed to select next variant:', result.error);
					toast.error('Failed to switch to next variant');
				}
			} catch (err) {
				console.error('Failed to select next variant:', err);
				toast.error('Failed to switch to next variant');
			}
		} else {
			// No more variants, generate a new one as a variant (not a retry)
			// Find the current message and the user message before it
			const messageIndex = (activeStreamingService.messages as StreamingMessage[]).findIndex(
				(msg) => msg.id === messageId || msg.backend_id === messageId
			);

			if (messageIndex > 0) {
				const userMessage = (activeStreamingService.messages as StreamingMessage[])[
					messageIndex - 1
				];
				if (userMessage.sender === 'user') {
					// Show regeneration modal for variant generation
					const backendMessageId = message.backend_id || messageId;
					pendingRegenerationData = {
						userMessage: userMessage.content,
						messageId: backendMessageId
					};
					showRegenerationModal = true;
				}
			}
		}
	}

	// Retry a failed assistant message
	async function handleRetryFailedMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Retry failed message:', messageId);

		// Find the failed assistant message
		const messageIndex = (activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const failedMessage = (activeStreamingService.messages as StreamingMessage[])[messageIndex];
		if (failedMessage.sender !== 'assistant' || !failedMessage.error) return;

		// Find the previous user message to regenerate from
		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = (activeStreamingService.messages as StreamingMessage[])[userMessageIndex];
		if (userMessage.sender !== 'user') return;

		// Remove the failed assistant message and any messages after it
		// This prevents the "Thinking..." state from getting stuck when streamingService creates a new message
		const allMessages = [...(activeStreamingService.messages as StreamingMessage[])];
		const messagesToRemove = allMessages.slice(messageIndex); // Include the failed message
		activeStreamingService.messages = allMessages.slice(0, messageIndex); // Keep only up to the user message

		// Variant data is now managed by the backend

		// Delete trailing messages from backend if they exist
		if (messagesToRemove.length > 0 && messagesToRemove[0].backend_id) {
			try {
				await _apiClient.deleteTrailingMessages(messagesToRemove[0].backend_id);
			} catch (err) {
				console.warn('Failed to delete trailing messages from backend during retry:', err);
				// Continue with retry even if cleanup fails
			}
		}

		// Show the regeneration modal to let user choose analysis mode (for retry after error)
		// Don't pass messageId for retry - this should be a fresh regeneration, not a variant
		pendingRegenerationData = { userMessage: userMessage.content, messageId: undefined };
		showRegenerationModal = true;
	}

	// Handle regeneration modal confirmation
	async function handleRegenerationConfirm(mode: AnalysisMode, guidance?: string) {
		if (!pendingRegenerationData) return;

		const { userMessage, messageId, targetMessageIndex, allMessages } = pendingRegenerationData;

		// IMMEDIATELY set loading state for variant generation (instant feedback)
		if (messageId) {
			const existingMessageIndex = (
				activeStreamingService.messages as StreamingMessage[]
			).findIndex((msg) => msg.id === messageId || msg.backend_id === messageId);

			if (existingMessageIndex !== -1) {
				const existingMessage = activeStreamingService.messages[existingMessageIndex];

				// Set immediate loading state
				activeStreamingService.messages[existingMessageIndex] = {
					...existingMessage,
					content: '',
					displayedContent: '',
					isRegenerating: true,
					error: undefined,
					retryable: false
				};

				// Force Svelte reactivity
				activeStreamingService.messages = [...activeStreamingService.messages];
			}
		}

		// NOW perform the cleanup that was deferred from handleRetryMessage
		// (This will NOT run for variant generation since those fields aren't set)
		if (targetMessageIndex !== undefined && allMessages) {
			console.log('🧹 Performing retry cleanup - deleting trailing messages');
			// Only delete trailing messages from backend (messages after the one we're regenerating)
			const messagesToDeleteFromBackend = allMessages.slice(targetMessageIndex + 1); // Messages AFTER the target

			if (messagesToDeleteFromBackend.length > 0 && messagesToDeleteFromBackend[0].backend_id) {
				try {
					await _apiClient.deleteTrailingMessages(messagesToDeleteFromBackend[0].backend_id);
				} catch (err) {
					console.warn('Failed to delete trailing messages from backend:', err);
					// Continue with regeneration even if cleanup fails
				}
			}

			// Remove trailing messages from UI (but keep the target message for variant update)
			activeStreamingService.messages = allMessages.slice(0, targetMessageIndex + 1);
		} else {
			console.log('🎯 Generating new variant - no cleanup needed');
		}

		let targetMessageFrontendId: string | undefined;
		if (targetMessageIndex !== undefined && allMessages && allMessages[targetMessageIndex]) {
			targetMessageFrontendId = allMessages[targetMessageIndex].id;
		}

		regenerateResponse(userMessage, messageId, mode, guidance, targetMessageFrontendId);

		// Clear pending data
		pendingRegenerationData = null;
		showRegenerationModal = false;
	}

	// Handle regeneration modal cancel
	function handleRegenerationCancel() {
		pendingRegenerationData = null;
		showRegenerationModal = false;
	}

	async function handleDeleteMessage(messageId: string) {
		if (!chat?.id || isLoading) return;

		console.log('Delete message:', messageId);

		// Find the message to delete
		const messageIndex = (activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		// Get the message before removing it
		const messageToDelete = (activeStreamingService.messages as StreamingMessage[])[messageIndex];

		// Remove the message from the UI immediately
		const allMessages = [...(activeStreamingService.messages as StreamingMessage[])];
		allMessages.splice(messageIndex, 1);
		activeStreamingService.messages = allMessages;

		// Variant data is now managed by the backend

		// Delete from backend if it has a backend ID
		if (messageToDelete?.backend_id || messageToDelete?.id) {
			try {
				await _apiClient.deleteMessage(messageToDelete.backend_id || messageToDelete.id);
				console.log('Message deleted from backend successfully');
			} catch (err) {
				console.error('Failed to delete message from backend:', err);
				// Note: We don't revert the UI change since the user intended to delete it
				// They can refresh to see the actual state if needed
			}
		}
	}

	// Handler to open extraction dialog
	function handleOpenExtractDialog() {
		if (!chat?.id) return;

		showExtractDialog = true;
	}

	// Handler for successful extraction
	function handleExtractionSuccess(entries: LorebookEntry[]) {
		const count = entries.length;
		if (count > 0) {
			toast.success(
				`Successfully extracted ${count} lorebook ${count === 1 ? 'entry' : 'entries'}`
			);
		} else {
			toast.info('No entries were extracted from the selected messages');
		}
	}
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
	<!-- ChatHeader type mismatch fixed by updating ChatHeader component -->
	<ChatHeader {chat} {readonly} onOpenExtractDialog={handleOpenExtractDialog} />
	{#key `${displayMessages.length}-${firstMessageVariantIndex}`}
		<!-- Messages component render key - includes variant index to force re-render -->
	{/key}

	<Messages
		{readonly}
		loading={isLoading}
		messages={displayMessages}
		selectedCharacterId={selectedCharacterStore.characterId}
		{character}
		{chat}
		{user}
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
		{substituteTemplateVariables}
		{userPersonaName}
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
					<!-- Upgrade Banner for Token Limit Warning -->
					{#if ENABLE_PAYMENTS && (subscriptionStore.isAtLimit || subscriptionStore.isNearLimit)}
						<div class="mb-3">
							<UpgradePrompt
								variant="banner"
								title={subscriptionStore.isAtLimit ? 'Token Limit Reached' : 'Near Token Limit'}
								message={subscriptionStore.isAtLimit
									? "You've reached your monthly token limit. Upgrade to continue chatting."
									: "You're approaching your monthly token limit. Consider upgrading to avoid interruptions."}
								showCloseButton={!subscriptionStore.isAtLimit}
							/>
						</div>
					{/if}

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
								promptTokens={tokenCounter.data?.total || 0}
								completionTokens={0}
								modelName={chat?.model_name}
								loading={tokenCounter.loading}
								isEstimate={true}
							/>
						</div>
					{/if}

					<!-- Session Total Display (from backend) -->
					{#if chat?.total_actual_cost || chat?.total_credits_used || chat?.total_prompt_tokens || chat?.total_completion_tokens}
						{@const sessionCost =
							chat.total_actual_cost !== undefined
								? chat.total_actual_cost
								: typeof chat.total_credits_used === 'string'
									? parseFloat(chat.total_credits_used)
									: chat.total_credits_used}
						{@const formatSessionCost = (cost: number | undefined) =>
							typeof cost !== 'number' || isNaN(cost) || cost < 0.0001
								? '<$0.0001'
								: `$${cost.toFixed(4)}`}
						{@const promptTokens = chat.total_prompt_tokens || 0}
						{@const completionTokens = chat.total_completion_tokens || 0}
						{@const totalTokens = promptTokens + completionTokens}

						<div class="mt-2 space-y-1 border-t pt-2 text-xs text-muted-foreground">
							<!-- Main breakdown -->
							<div class="flex items-center justify-between">
								<span class="font-medium">Session Usage:</span>
								<div class="flex items-center gap-2">
									<span class="text-blue-600 dark:text-blue-400">
										↑{promptTokens.toLocaleString()} input
									</span>
									<span class="text-green-600 dark:text-green-400">
										↓{completionTokens.toLocaleString()} output
									</span>
									<span class="font-medium">
										{totalTokens.toLocaleString()} total
									</span>
									{#if sessionCost !== undefined}
										<span class="font-mono font-medium text-amber-600 dark:text-amber-400">
											{formatSessionCost(sessionCost)}
										</span>
									{/if}
								</div>
							</div>

							<!-- Note about system context -->
							<div class="text-center text-xs opacity-75">
								Base API cost (authoritative from backend) • Hover messages for individual costs
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
<ChronicleOptInDialog
	open={showChronicleOptIn}
	onConfirm={handleChronicleChoice}
	onOpenChange={(newOpen) => {
		console.log('[Chat] ChronicleDialog onOpenChange:', newOpen);
		showChronicleOptIn = newOpen;
	}}
/>

<!-- Regeneration Options Modal -->
<RegenerationModal
	bind:open={showRegenerationModal}
	onConfirm={handleRegenerationConfirm}
	onCancel={handleRegenerationCancel}
/>

<!-- Upgrade Prompt Modal -->
{#if showUpgradePrompt}
	<UpgradePrompt
		variant="modal"
		on:close={() => (showUpgradePrompt = false)}
		on:upgrade={() => (showUpgradePrompt = false)}
	/>
{/if}

<!-- Lorebook Extraction Dialog -->
{#if chat?.id}
	<LorebookExtractionDialog
		bind:open={showExtractDialog}
		chatSessionId={chat.id}
		messages={displayMessages.map((msg, index) => ({
			role: msg.message_type.toLowerCase(),
			content: msg.content,
			index
		}))}
		lorebooks={availableLorebooks}
		onOpenChange={(open) => (showExtractDialog = open)}
		onSuccess={handleExtractionSuccess}
	/>
{/if}
