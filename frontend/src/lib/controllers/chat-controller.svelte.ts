import { toast } from 'svelte-sonner';
import { apiClient as _apiClient } from '$lib/api';
import type {
	User,
	ScribeCharacter,
	Message,
	ScribeChatSession,
	ScribeChatMessage
} from '$lib/types';
import type { StreamingMessage } from '$lib/services/StreamingService.svelte';
import { desktopStreamingService } from '$lib/services/DesktopStreamingService.svelte';
import { streamingService } from '$lib/services/StreamingService.svelte';
import { isInDesktopMode } from '$lib/api/desktop-auth';
import { tick } from 'svelte';
import type { AnalysisMode } from '$lib/components/messages/regeneration-modal.svelte';
import { ChatHistory } from '$lib/hooks/chat-history.svelte';
import { extractMessageContent } from '$lib/utils/message-helpers';

export class ChatController {
	// State
	chat = $state<ScribeChatSession | undefined>(undefined);
	user = $state<User | undefined>(undefined);
	character = $state<ScribeCharacter | null | undefined>(undefined);

	// Pagination
	nextCursor = $state<string | null>(null);
	isLoadingMore = $state(false);
	hasMoreMessages = $state(false);
	loadedMessagesBatches = $state<ScribeChatMessage[][]>([]);
	suppressAutoScroll = $state(false);

	// Input
	chatInput = $state('');

	// Cache
	messageCache = new Map<string, ScribeChatMessage>();
	lastStreamingMessages: unknown[] = [];

	// Regeneration
	showRegenerationModal = $state(false);
	pendingRegenerationData = $state<{
		userMessage: string;
		messageId?: string;
		targetMessageIndex?: number;
		allMessages?: StreamingMessage[];
	} | null>(null);

	// Suggested Actions
	dynamicSuggestedActions = $state<Array<{ action: string }>>([]);
	isLoadingSuggestions = $state(false);
	suggestionsError = $state<string | null>(null);

	suggestionsRetryable = $state(false);

	// Chronicles
	// Setup Dialog (Chronicles & Game Master)
	showSetupDialog = $state(false);
	chroniclePreference = $state<boolean | null>(null);
	gameMasterPreference = $state<boolean | null>(null);
	hasExplicitSetupChoice = $state(false);
	pendingMessage = $state<string | null>(null);

	// Agent Mode
	agentMode = $state<'disabled' | 'pre_processing' | 'post_processing'>('disabled');

	// Dependencies
	chatHistory = ChatHistory.fromContext();

	constructor(
		chat: ScribeChatSession | undefined,
		user: User | undefined,
		character: ScribeCharacter | null | undefined,
		initialMessages: ScribeChatMessage[],
		initialCursor: string | null = null,
		initialChatInputValue: string = ''
	) {
		this.chat = chat;
		this.user = user;
		this.character = character;
		this.loadedMessagesBatches = [initialMessages];
		this.nextCursor = initialCursor;
		this.hasMoreMessages = initialCursor !== null;
		this.chatInput = initialChatInputValue;

		// Load preferences
		if (typeof localStorage !== 'undefined') {
			const chroniclePref = localStorage.getItem('chroniclePreference');
			if (chroniclePref !== null) {
				this.chroniclePreference = chroniclePref === 'true';
			}
			const gmPref = localStorage.getItem('gameMasterPreference');
			if (gmPref !== null) {
				this.gameMasterPreference = gmPref === 'true';
			}
		}
	}

	get activeStreamingService() {
		return isInDesktopMode() ? desktopStreamingService : streamingService;
	}

	get messages() {
		// ... logic from displayMessages derived ...
		return this.getDisplayMessages();
	}

	get isLoading() {
		return (
			this.activeStreamingService.connectionStatus === 'connecting' ||
			this.activeStreamingService.connectionStatus === 'open' ||
			this.activeStreamingService.messages.some((msg) => msg.isAnimating === true)
		);
	}

	getDisplayMessages() {
		try {
			const streamingMessages = this.activeStreamingService.messages;

			if (
				streamingMessages === this.lastStreamingMessages ||
				(Array.isArray(this.lastStreamingMessages) &&
					streamingMessages.length === this.lastStreamingMessages.length &&
					streamingMessages.every((msg, idx) => msg === this.lastStreamingMessages[idx]))
			) {
				// Using cached result - no change detected
				return Array.from(this.messageCache.values());
			}

			// Processing new messages array
			const messages: ScribeChatMessage[] = [];
			const newCache = new Map<string, ScribeChatMessage>();

			streamingMessages.forEach((msg) => {
				const cached = this.messageCache.get(msg.id);

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
						session_id: this.chat?.id ?? 'unknown-session',
						message_type: msg.sender === 'user' ? ('User' as const) : ('Assistant' as const),
						content: displayContent, // Use displayedContent for UI rendering
						created_at: msg.created_at,
						user_id: msg.sender === 'user' ? (this.user?.id ?? '') : '',
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
						shouldAnimate: msg.shouldAnimate,
						variants: msg.variants
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
			this.messageCache = newCache;
			this.lastStreamingMessages = streamingMessages;

			// Sort messages by timestamp (oldest first) for proper chronological display
			messages.sort((a, b) => {
				const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
				const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;
				return aTime - bTime;
			});

			return messages;
		} catch (_error) {
			console.error('❌ Error in displayMessages derived:', _error);
			// Return cached messages if available, otherwise return empty array
			return Array.from(this.messageCache.values());
		}
	}

	async loadMoreMessages(retryCount = 0) {
		if (!this.chat?.id || this.isLoadingMore || !this.hasMoreMessages || !this.nextCursor) {
			return;
		}

		if (retryCount > 3) {
			console.warn('🛑 [loadMoreMessages] Max retries reached. Stopping infinite load.');
			this.isLoadingMore = false;
			this.suppressAutoScroll = false;
			return;
		}

		this.isLoadingMore = true;
		this.suppressAutoScroll = true;

		try {
			const currentCursor = this.nextCursor;
			const result = await _apiClient.getMessagesByChatId(this.chat.id, {
				limit: 20,
				cursor: currentCursor
			});

			if (result.isErr()) {
				console.error('Failed to load more messages:', result.error);
				toast.error('Failed to load older messages');
				return;
			}

			// Handle paginated response
			if (!Array.isArray(result.value) && 'messages' in result.value) {
				const { messages: newMessages, nextCursor: newCursor } = result.value;

				// 0. Safety Check: If backend returns the same cursor, we are stuck.
				if (newCursor === currentCursor && newMessages.length === 0) {
					console.warn(
						'🛑 [loadMoreMessages] Backend returned same cursor with no messages. Stopping.'
					);
					this.hasMoreMessages = false;
					this.nextCursor = null;
					this.suppressAutoScroll = false;
					return;
				}

				// 1. Update Pagination State (Source of Truth)
				// We update this immediately because the API has confirmed where the next page is.
				// This prevents getting stuck even if the current batch is all duplicates.
				this.nextCursor = newCursor;
				this.hasMoreMessages = newCursor !== null;

				console.log('📥 Loading more messages:', {
					newMessagesCount: newMessages.length,
					newCursor,
					currentStreamingCount: this.activeStreamingService.messages.length
				});

				// 2. Data Transformation
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
						parent_message_id: rawMsg.parent_message_id,
						variants: rawMsg.variants,
						game_state: rawMsg.game_state
					})
				);

				// 3. Deduplication (Business Logic)
				// Convert to StreamingMessage format
				const streamingMessages = convertedMessages.map(
					(msg): StreamingMessage => ({
						id: msg.id,
						sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
						content: msg.content,
						displayedContent: msg.content,
						created_at: msg.created_at || new Date().toISOString(),
						isAnimating: false,
						shouldAnimate: msg.shouldAnimate ?? false,
						error: msg.error || undefined,
						retryable: msg.retryable,
						prompt_tokens: msg.prompt_tokens || undefined,
						completion_tokens: msg.completion_tokens || undefined,
						model_name: msg.model_name,
						backend_id: msg.backend_id,
						status: msg.status,
						superseded_at: msg.superseded_at,
						variant_count: msg.variant_count,
						current_variant_index: msg.current_variant_index,
						is_variant: msg.is_variant,
						parent_message_id: msg.parent_message_id,
						variants: msg.variants,
						contentVersion: 0,
						game_state: msg.game_state as unknown as Record<string, unknown> | null
					})
				);

				const existingIds = new Set(this.activeStreamingService.messages.map((m) => m.id));
				const existingBackendIds = new Set(
					this.activeStreamingService.messages
						.map((m) => m.backend_id)
						.filter((id): id is string => !!id)
				);

				const uniqueNewMessages = streamingMessages.filter((msg) => {
					const idExists = existingIds.has(msg.id);
					const backendIdExists = msg.backend_id && existingBackendIds.has(msg.backend_id);
					return !idExists && !backendIdExists;
				});

				// 4. Handle "Empty Batch" Case
				if (uniqueNewMessages.length === 0) {
					console.log('⚠️ [loadMoreMessages] No new messages found after deduplication.');

					// Safety check: If the API returned 0 messages, we should stop regardless of cursor
					if (newMessages.length === 0) {
						console.log('🛑 [loadMoreMessages] API returned empty message list. Stopping.');
						this.hasMoreMessages = false;
						this.nextCursor = null;
						this.suppressAutoScroll = false;
						return;
					}

					// Critical Fix: If we have more messages on the server (hasMoreMessages is true),
					// but this batch was all duplicates, we MUST try the next batch immediately.
					// Otherwise the user is stuck at the top with no way to trigger a load.
					if (this.hasMoreMessages) {
						console.log(
							`🔄 [loadMoreMessages] Automatically fetching next batch (retry ${retryCount + 1})...`
						);
						// Release the lock briefly to allow the recursive call to proceed
						this.isLoadingMore = false;
						await this.loadMoreMessages(retryCount + 1);
						return;
					}

					// If no more messages on server, we are truly done.
					this.suppressAutoScroll = false;
					return;
				}

				console.log(`✅ [loadMoreMessages] Prepending ${uniqueNewMessages.length} unique messages`);

				// 5. UI State Preservation (Scroll)
				const messagesContainer =
					document.querySelector('[data-messages-container]') ||
					document.querySelector('.overflow-y-scroll');

				let distanceFromBottom = 0;
				if (messagesContainer) {
					const oldScrollTop = messagesContainer.scrollTop;
					const oldScrollHeight = messagesContainer.scrollHeight;
					const containerHeight = messagesContainer.clientHeight;
					distanceFromBottom = oldScrollHeight - oldScrollTop - containerHeight;
				}

				// 6. State Mutation
				this.activeStreamingService.messages = [
					...uniqueNewMessages,
					...this.activeStreamingService.messages
				];
				this.loadedMessagesBatches.push(convertedMessages);

				// 7. UI Update (Restore Scroll)
				if (messagesContainer) {
					await tick();
					const newScrollHeight = messagesContainer.scrollHeight;
					const newContainerHeight = messagesContainer.clientHeight;
					const targetScrollTop = newScrollHeight - distanceFromBottom - newContainerHeight;

					messagesContainer.scrollTop = targetScrollTop;

					// Double-check scroll position after a short delay to handle dynamic content resizing
					await tick();
					setTimeout(() => {
						if (messagesContainer) {
							messagesContainer.scrollTop = targetScrollTop;
						}
						this.suppressAutoScroll = false;
					}, 150);
				} else {
					this.suppressAutoScroll = false;
				}
			}
		} catch (_error) {
			console.error('Error loading more messages:', _error);
			toast.error('Failed to load older messages');
		} finally {
			this.isLoadingMore = false;
			// Ensure suppressAutoScroll is cleared even if there's an error
			if (this.suppressAutoScroll) {
				setTimeout(() => {
					this.suppressAutoScroll = false;
				}, 200);
			}
		}
	}

	// ... (loadMoreMessages implementation) ...

	// Track last initialized chat ID to prevent unnecessary resets
	private lastInitializedChatId: string | null = null;

	initializeChat() {
		if (!this.chat?.id) return;

		// Prevent re-initialization if we're already on this chat
		if (this.lastInitializedChatId === this.chat.id) {
			console.log(
				`🔄 [initializeChat] Skipping initialization - already initialized for ${this.chat.id}`
			);
			return;
		}

		console.log(`🚀 [initializeChat] Initializing chat ${this.chat.id}`);
		this.lastInitializedChatId = this.chat.id;

		// CRITICAL: Always clear messages first to prevent stale state from previous chats
		// This fixes the bug where navigating away and back shows the previous chat's messages
		this.activeStreamingService.clearMessages();

		// Logic to populate initial messages
		if (this.chat?.id) {
			const initialMessages = this.loadedMessagesBatches[0] || [];

			if (initialMessages.length > 0) {
				console.log(`📥 Initializing chat ${this.chat.id} with ${initialMessages.length} messages`);

				// Convert ScribeChatMessage to StreamingMessage
				const streamingMessages = initialMessages.map(
					(msg): StreamingMessage => ({
						id: msg.id,
						sender: msg.message_type === 'Assistant' ? 'assistant' : 'user',
						content: msg.content,
						displayedContent: msg.content,
						created_at: msg.created_at || new Date().toISOString(),
						isAnimating: false,
						shouldAnimate: msg.shouldAnimate ?? false, // Carry over shouldAnimate flag (false for historical)
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
						variants: msg.variants,
						contentVersion: 0, // Initialize for Svelte 5 reactivity
						game_state: msg.game_state as unknown as Record<string, unknown> | null
					})
				);

				// Populate streaming service
				this.activeStreamingService.messages = streamingMessages;

				// CRITICAL: Initialize game state from the last message that has it
				// This ensures the UI shows the correct state when loading a chat
				console.log(
					`🎮 [initializeChat] Checking ${streamingMessages.length} messages for game_state`
				);
				streamingMessages.forEach((m, i) => {
					console.log(
						`🎮 [initializeChat] Message ${i}: id=${m.id?.slice(-8)}, sender=${m.sender}, has_game_state=${!!m.game_state}`
					);
				});

				const lastMessageWithState = [...streamingMessages].reverse().find((m) => m.game_state);

				if (lastMessageWithState?.game_state) {
					console.log(
						`🎮 [initializeChat] Restoring game state from message ${lastMessageWithState.id}`
					);
					this.activeStreamingService.latestGameState = lastMessageWithState.game_state;
				} else {
					console.log(`🎮 [initializeChat] No messages have game_state - state will be empty`);
				}
			}
		}
	}

	async sendMessage(content: string) {
		console.log('🚨🚨🚨 SENDMESSAGE START - content:', content.slice(0, 50) + '...');

		if (!this.chat?.id || !this.user?.id) {
			console.error('❌ [sendMessage] Missing chat.id or user.id - EARLY RETURN');
			toast.error('Chat session or user information is missing.');
			return;
		}

		// Check if we need to show setup dialog
		// Show if: first user message AND (no chronicle OR no GM setting) AND no explicit choice made
		const _isFirst = this.isFirstUserMessage();

		if (
			_isFirst &&
			!this.hasExplicitSetupChoice &&
			((!this.chat?.player_chronicle_id && this.chroniclePreference === null) ||
				(!this.chat?.game_master_mode_enabled && this.gameMasterPreference === null))
		) {
			console.log('📖 [sendMessage] SHOWING SETUP DIALOG');
			this.pendingMessage = content;
			this.showSetupDialog = true;
			return;
		}

		// If user has saved preferences, apply them automatically
		// BUT only if they haven't made an explicit choice for this session
		if (_isFirst && !this.hasExplicitSetupChoice) {
			const shouldCreateChronicle =
				!this.chat?.player_chronicle_id && this.chroniclePreference === true;
			const shouldEnableGM =
				!this.chat?.game_master_mode_enabled && this.gameMasterPreference === true;

			if (shouldCreateChronicle || shouldEnableGM) {
				console.log('📖 [sendMessage] Auto-applying preferences...');
				try {
					await this.applySetupChoices({
						enableChronicle: shouldCreateChronicle,
						enableGameMaster: shouldEnableGM,
						rememberChoice: false // Already remembered
					});
				} catch (error) {
					console.error('❌ [sendMessage] Failed to auto-apply preferences:', error);
				}
			}
		}

		await this.sendMessageInternal(content);
	}

	isFirstUserMessage(): boolean {
		// Check if there are any user messages in the current messages
		const hasUserMessage = this.activeStreamingService.messages.some(
			(msg) => msg.sender === 'user'
		);
		return !hasUserMessage;
	}

	async handleSetupChoice(options: {
		enableChronicle: boolean;
		enableGameMaster: boolean;
		rememberChoice: boolean;
	}) {
		// Mark that user made an explicit choice for this session
		this.hasExplicitSetupChoice = true;

		if (options.rememberChoice && typeof localStorage !== 'undefined') {
			localStorage.setItem('chroniclePreference', String(options.enableChronicle));
			this.chroniclePreference = options.enableChronicle;

			localStorage.setItem('gameMasterPreference', String(options.enableGameMaster));
			this.gameMasterPreference = options.enableGameMaster;
		}

		await this.applySetupChoices(options);

		// Send the pending message first
		if (this.pendingMessage) {
			const message = this.pendingMessage;
			this.pendingMessage = null;
			await this.sendMessageInternal(message);
		}

		// CRITICAL: Wait for next tick before closing dialog
		await tick();
		this.showSetupDialog = false;
	}

	async applySetupChoices(options: {
		enableChronicle: boolean;
		enableGameMaster: boolean;
		rememberChoice: boolean;
	}) {
		if (!this.chat?.id) return;

		const promises = [];

		if (options.enableChronicle && !this.chat.player_chronicle_id) {
			promises.push(this.createChronicleForChat());
		}

		if (options.enableGameMaster && !this.chat.game_master_mode_enabled) {
			promises.push(this.enableGameMasterForChat());
		}

		await Promise.all(promises);
	}

	async enableGameMasterForChat() {
		if (!this.chat?.id) return;
		try {
			const result = await _apiClient.updateChatSessionSettings(this.chat.id, {
				game_master_mode_enabled: true
			} as any);
			if (result.isOk()) {
				this.chat.game_master_mode_enabled = true;
				toast.success('Game Master Mode enabled');
			} else {
				console.error('Failed to enable Game Master Mode:', result.error);
				toast.error('Failed to enable Game Master Mode');
			}
		} catch (error) {
			console.error('Error enabling Game Master Mode:', error);
			toast.error('Error enabling Game Master Mode');
		}
	}

	async createChronicleForChat() {
		if (!this.chat?.id) return;

		try {
			// Generate an AI-powered chronicle name
			let chronicleName = this.chat.title || 'New Chronicle';

			try {
				console.log('Generating AI chronicle name for chat:', this.chat.id);
				const nameResult = await _apiClient.generateChronicleName(this.chat.id);

				if (nameResult.isOk()) {
					chronicleName = nameResult.value.name;
					console.log('Generated chronicle name:', chronicleName);
				} else {
					console.warn('Failed to generate AI chronicle name, using fallback:', nameResult.error);
				}
			} catch (_error) {
				console.warn('Error generating AI chronicle name, using fallback:', _error);
			}

			// Create a new chronicle with the generated/fallback name
			const chronicleResult = await _apiClient.createChronicle({
				name: chronicleName,
				description: `Chronicle for ${this.chat.title || 'chat session'}`
			});

			if (chronicleResult.isOk()) {
				const chronicle = chronicleResult.value;

				// Update chat to associate with the chronicle
				const updateResult = await _apiClient.updateChatSessionSettings(this.chat.id, {
					chronicle_id: chronicle.id
				});

				if (updateResult.isOk()) {
					// Update local chat object
					this.chat.player_chronicle_id = chronicle.id;
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
			console.error('Error in createChronicleForChat:', error);
			toast.error('An error occurred while creating the chronicle');
		}
	}

	async sendMessageInternal(content: string) {
		if (!this.chat?.id || !this.user?.id) {
			return;
		}

		// Build history
		const existingHistoryForApi = (this.activeStreamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false))
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		try {
			const currentModel = await this.getCurrentChatModel();

			await this.activeStreamingService.connect({
				chatId: this.chat.id,
				userMessage: content,
				history: existingHistoryForApi,
				model: currentModel || undefined,
				agentMode: this.agentMode
			});

			// Refresh chat metadata
			// await this.refreshChatMetadata();
		} catch (_error) {
			console.error('❌ Failed to send message:', _error);
			toast.error('Failed to send message. Please try again.');
		}
	}

	stopGeneration() {
		if (isInDesktopMode()) {
			// It's DesktopStreamingService
			(
				this.activeStreamingService as unknown as { stopCurrentStream: () => void }
			).stopCurrentStream();
		} else {
			(this.activeStreamingService as unknown as { interrupt?: () => void }).interrupt?.();
		}
	}

	async getCurrentChatModel() {
		if (!this.chat?.id) return null;
		try {
			const result = await _apiClient.getChatSessionSettings(this.chat.id);
			if (result.isOk()) {
				return result.value.model_name || null;
			}
		} catch (_error) {
			console.error('Failed to get chat model:', _error);
		}
		return null;
	}

	async fetchSuggestedActions() {
		if (!this.chat?.id) return;

		try {
			this.isLoadingSuggestions = true;
			this.suggestionsError = null;
			this.suggestionsRetryable = false;

			const result = await _apiClient.fetchSuggestedActions(this.chat.id);

			if (result.isOk()) {
				const responseData = result.value;
				if (responseData.suggestions && responseData.suggestions.length > 0) {
					this.dynamicSuggestedActions = responseData.suggestions;
				} else {
					this.dynamicSuggestedActions = [];
				}
			} else {
				this.suggestionsError = result.error.message;
				this.suggestionsRetryable = true;
				this.dynamicSuggestedActions = [];
			}
		} catch (err) {
			this.suggestionsError = (err as Error).message;
			this.suggestionsRetryable = true;
			this.dynamicSuggestedActions = [];
		} finally {
			this.isLoadingSuggestions = false;
		}
	}

	substituteTemplateVariables(
		text: string,
		characterName: string,
		userPersonaName?: string
	): string {
		if (!text) return text;
		const nameToUse = userPersonaName || this.user?.username || 'User';
		return text.replace(/\{\{char\}\}/g, characterName).replace(/\{\{user\}\}/g, nameToUse);
	}

	handleInputSubmit(e: Event) {
		e.preventDefault();
		if (this.chatInput.trim() && !this.isLoading) {
			this.sendMessage(this.chatInput.trim());
			this.chatInput = '';
		}
	}

	async regenerateResponse(
		_userMessageContent: string,
		originalMessageId?: string,
		analysisMode: AnalysisMode = 'existing',
		guidance?: string,
		targetMessageId?: string
	) {
		if (!this.chat?.id || !this.user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		if (this.isLoading) {
			toast.warning('Please wait for the current message to complete.');
			return;
		}

		const historyToSend = (this.activeStreamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false))
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		console.log('DEBUG: regenerateResponse historyToSend:', JSON.stringify(historyToSend));
		console.log('DEBUG: regenerateResponse guidance:', guidance);

		const lastUserMessage = historyToSend.filter((h) => h.role === 'user').pop();
		if (!lastUserMessage) {
			toast.error('No user message found to regenerate response.');
			return;
		}

		try {
			const currentModel = await this.getCurrentChatModel();

			let targetMessageIdForVariant: string | undefined = targetMessageId;
			if (!targetMessageIdForVariant && originalMessageId) {
				const currentMessages = this.activeStreamingService.messages as StreamingMessage[];
				const targetMessage = currentMessages.find(
					(msg) => msg.backend_id === originalMessageId || msg.id === originalMessageId
				);
				if (targetMessage) {
					targetMessageIdForVariant = targetMessage.id;
				}
			}
			console.log('DEBUG: regenerateResponse originalMessageId:', originalMessageId);
			console.log(
				'DEBUG: regenerateResponse targetMessageIdForVariant:',
				targetMessageIdForVariant
			);

			const lastHistoryMessage = historyToSend[historyToSend.length - 1];
			const shouldSliceHistory = lastHistoryMessage?.role !== 'user';
			const finalHistory = shouldSliceHistory ? historyToSend.slice(0, -1) : historyToSend;
			console.log('DEBUG: regenerateResponse finalHistory:', JSON.stringify(finalHistory));

			await this.activeStreamingService.connect({
				chatId: this.chat.id,
				userMessage: lastUserMessage.content,
				history: finalHistory,
				model: currentModel || undefined,
				agentMode: this.agentMode,
				analysisMode: analysisMode,
				isRegeneration: true,
				guidance: guidance,
				targetMessageId: targetMessageIdForVariant,
				variantOf: originalMessageId
			});

			// await this.refreshChatMetadata();
			const preview = lastUserMessage.content.substring(0, 100);
			this.chatHistory.updateChatPreview(this.chat.id, preview);
		} catch (_error) {
			console.error('Failed to regenerate response:', _error);
			toast.error('Failed to regenerate response. Please try again.');
		}
	}

	async handleRegenerationConfirm(mode: AnalysisMode, guidance?: string) {
		if (!this.pendingRegenerationData) return;

		const { userMessage, messageId, targetMessageIndex, allMessages } =
			this.pendingRegenerationData;

		if (targetMessageIndex !== undefined && allMessages) {
			const messagesToDeleteFromBackend = allMessages.slice(targetMessageIndex + 1);
			if (messagesToDeleteFromBackend.length > 0 && messagesToDeleteFromBackend[0].backend_id) {
				try {
					await _apiClient.deleteTrailingMessages(messagesToDeleteFromBackend[0].backend_id);
				} catch (err) {
					console.warn('Failed to delete trailing messages from backend:', err);
				}
			}
			this.activeStreamingService.messages = allMessages.slice(0, targetMessageIndex + 1);
		}

		if (messageId) {
			const existingMessageIndex = (
				this.activeStreamingService.messages as StreamingMessage[]
			).findIndex((msg) => msg.id === messageId || msg.backend_id === messageId);

			if (existingMessageIndex !== -1) {
				const existingMessage = this.activeStreamingService.messages[existingMessageIndex];
				this.activeStreamingService.messages[existingMessageIndex] = {
					...existingMessage,
					content: '',
					displayedContent: '',
					isRegenerating: true,
					error: undefined,
					retryable: false
				};
				this.activeStreamingService.messages = [...this.activeStreamingService.messages];
			}
		}

		let targetMessageFrontendId: string | undefined;
		if (targetMessageIndex !== undefined && allMessages && allMessages[targetMessageIndex]) {
			targetMessageFrontendId = allMessages[targetMessageIndex].id;
		}

		this.regenerateResponse(userMessage, messageId, mode, guidance, targetMessageFrontendId);
		this.pendingRegenerationData = null;
		this.showRegenerationModal = false;
	}

	handleRegenerationCancel() {
		this.pendingRegenerationData = null;
		this.showRegenerationModal = false;
	}

	async generateAIResponse() {
		if (!this.chat?.id || !this.user?.id) {
			toast.error('Chat session or user information is missing.');
			return;
		}

		const historyToSend = (this.activeStreamingService.messages as StreamingMessage[])
			.filter((m) => !(m.isAnimating ?? false))
			.map((m) => ({
				role: m.sender,
				content: m.content
			}));

		try {
			const lastUserMessage = historyToSend.filter((h) => h.role === 'user').pop();
			if (!lastUserMessage) {
				toast.error('No user message found to generate response.');
				return;
			}

			const currentModel = await this.getCurrentChatModel();
			await this.activeStreamingService.connect({
				chatId: this.chat.id,
				userMessage: lastUserMessage.content,
				history: historyToSend.slice(0, -1),
				model: currentModel || undefined,
				agentMode: this.agentMode
			});
		} catch (_error) {
			console.error('Failed to generate AI response:', _error);
			toast.error('Failed to generate response. Please try again.');
		}
	}

	handleRetryMessage(messageId: string) {
		if (!this.chat?.id || this.isLoading) return;

		const messageIndex = (this.activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const targetMessage = (this.activeStreamingService.messages as StreamingMessage[])[
			messageIndex
		];
		if (targetMessage.sender !== 'assistant') return;

		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = (this.activeStreamingService.messages as StreamingMessage[])[
			userMessageIndex
		];
		if (userMessage.sender !== 'user') return;

		const backendMessageId = targetMessage.backend_id || messageId;

		this.pendingRegenerationData = {
			userMessage: userMessage.content,
			messageId: backendMessageId,
			targetMessageIndex: messageIndex,
			allMessages: [...(this.activeStreamingService.messages as StreamingMessage[])]
		};
		this.showRegenerationModal = true;
	}

	handleRetryFailedMessage(messageId: string) {
		if (!this.chat?.id || this.isLoading) return;

		const messageIndex = (this.activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const failedMessage = (this.activeStreamingService.messages as StreamingMessage[])[
			messageIndex
		];
		if (failedMessage.sender !== 'assistant' || !failedMessage.error) return;

		const userMessageIndex = messageIndex - 1;
		if (userMessageIndex < 0) return;

		const userMessage = (this.activeStreamingService.messages as StreamingMessage[])[
			userMessageIndex
		];
		if (userMessage.sender !== 'user') return;

		const allMessages = [...(this.activeStreamingService.messages as StreamingMessage[])];
		const messagesToRemove = allMessages.slice(messageIndex);
		this.activeStreamingService.messages = allMessages.slice(0, messageIndex);

		if (messagesToRemove.length > 0 && messagesToRemove[0].backend_id) {
			_apiClient.deleteTrailingMessages(messagesToRemove[0].backend_id).catch(console.warn);
		}

		this.pendingRegenerationData = {
			userMessage: userMessage.content,
			messageId: undefined
		};
		this.showRegenerationModal = true;
	}

	handleEditMessage(messageId: string) {
		console.log('Edit message:', messageId);
	}

	async handleSaveEditedMessage(messageId: string, newContent: string) {
		if (!this.chat?.id || this.isLoading) return;

		const messageIndex = (this.activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const targetMessage = (this.activeStreamingService.messages as StreamingMessage[])[
			messageIndex
		];
		if (targetMessage.sender !== 'user') return;

		const allMessages = [...(this.activeStreamingService.messages as StreamingMessage[])];
		allMessages[messageIndex].content = newContent;

		const removedMessages = allMessages.slice(messageIndex + 1);
		this.activeStreamingService.messages = allMessages.slice(0, messageIndex + 1);

		if (removedMessages.length > 0 && removedMessages[0].backend_id) {
			_apiClient.deleteTrailingMessages(removedMessages[0].backend_id).catch(console.warn);
		}

		this.generateAIResponse();
	}

	async handleDeleteMessage(messageId: string) {
		if (!this.chat?.id || this.isLoading) return;

		const messageIndex = (this.activeStreamingService.messages as StreamingMessage[]).findIndex(
			(msg) => msg.id === messageId
		);
		if (messageIndex === -1) return;

		const messageToDelete = (this.activeStreamingService.messages as StreamingMessage[])[
			messageIndex
		];
		const allMessages = [...(this.activeStreamingService.messages as StreamingMessage[])];
		allMessages.splice(messageIndex, 1);
		this.activeStreamingService.messages = allMessages;

		if (messageToDelete?.backend_id || messageToDelete?.id) {
			try {
				await _apiClient.deleteMessage(messageToDelete.backend_id || messageToDelete.id);
			} catch (err) {
				console.error('Failed to delete message from backend:', err);
			}
		}
	}

	async handlePreviousVariant(messageId: string) {
		const message = this.activeStreamingService.messages.find(
			(msg) => msg.id === messageId || msg.backend_id === messageId
		);
		if (!message) return;

		const currentIndex = message.current_variant_index ?? 0;
		const variantCount = message.variant_count ?? 0;

		// Allow cycling back to variant 0 (original)
		if (variantCount > 0 && currentIndex > 0) {
			const newIndex = currentIndex - 1;

			try {
				const apiMessageId = message.backend_id || messageId;
				const result = await _apiClient.selectMessageVariant(apiMessageId, {
					variant_index: newIndex
				});

				if (result.isOk()) {
					const updatedMessage = result.value;

					// Update game state if available (Game Master Mode)
					if (this.chat && updatedMessage.game_state !== undefined) {
						this.chat.game_state = updatedMessage.game_state;
					}

					this.activeStreamingService.messages = (
						this.activeStreamingService.messages as StreamingMessage[]
					).map((msg) => {
						if (msg.id === messageId || msg.backend_id === messageId) {
							return {
								...msg,
								content: updatedMessage.content,
								current_variant_index: updatedMessage.current_variant_index,
								displayedContent: updatedMessage.content,
								prompt_tokens: updatedMessage.prompt_tokens ?? undefined,
								completion_tokens: updatedMessage.completion_tokens ?? undefined,
								model_name: updatedMessage.model_name ?? undefined,
								shouldAnimate: false, // Don't animate when switching to previous variant
								backend_id: updatedMessage.id // Update backend ID to match the selected variant
							};
						}
						return msg;
					});
				}
			} catch (_err) {
				toast.error('Failed to switch to previous variant');
			}
		}
	}

	async handleNextVariant(messageId: string) {
		const message = this.activeStreamingService.messages.find(
			(msg) => msg.id === messageId || msg.backend_id === messageId
		);
		if (!message) return;

		const currentIndex = message.current_variant_index ?? 0;
		const variantCount = message.variant_count ?? 0;

		if (variantCount > 0 && currentIndex < variantCount - 1) {
			const newIndex = currentIndex + 1;
			try {
				const apiMessageId = message.backend_id || messageId;
				const result = await _apiClient.selectMessageVariant(apiMessageId, {
					variant_index: newIndex
				});

				if (result.isOk()) {
					const updatedMessage = result.value;
					this.activeStreamingService.messages = (
						this.activeStreamingService.messages as StreamingMessage[]
					).map((msg) => {
						if (msg.id === messageId || msg.backend_id === messageId) {
							return {
								...msg,
								content: updatedMessage.content,
								current_variant_index: updatedMessage.current_variant_index,
								variant_count: updatedMessage.variant_count,
								displayedContent: updatedMessage.content,
								prompt_tokens: updatedMessage.prompt_tokens ?? undefined,
								completion_tokens: updatedMessage.completion_tokens ?? undefined,
								model_name: updatedMessage.model_name ?? undefined,
								shouldAnimate: false, // Don't animate when switching to existing next variant
								backend_id: updatedMessage.id // Update backend ID to match the selected variant
							};
						}
						return msg;
					});
				} else {
					this.regenerateResponse(
						'',
						message.backend_id || messageId,
						'existing',
						undefined,
						message.id
					);
				}
			} catch (_err) {
				toast.error('Failed to switch to next variant');
			}
		} else {
			// We are at the last variant, so we want to generate a new one.
			// Instead of regenerating immediately, we show the regeneration modal
			// to allow the user to provide guidance or choose analysis mode.

			const messageIndex = (this.activeStreamingService.messages as StreamingMessage[]).findIndex(
				(msg) => msg.id === messageId || msg.backend_id === messageId
			);

			if (messageIndex !== -1) {
				const userMessageIndex = messageIndex - 1;
				if (userMessageIndex >= 0) {
					const userMessage = (this.activeStreamingService.messages as StreamingMessage[])[
						userMessageIndex
					];

					if (userMessage.sender === 'user') {
						this.pendingRegenerationData = {
							userMessage: userMessage.content,
							messageId: message.backend_id || messageId,
							targetMessageIndex: messageIndex,
							allMessages: [...(this.activeStreamingService.messages as StreamingMessage[])]
						};
						this.showRegenerationModal = true;
						return;
					}
				}
			}

			// Fallback if we can't find the user message (shouldn't happen in normal flow)
			// Set loading state immediately before regeneration starts
			this.activeStreamingService.messages = (
				this.activeStreamingService.messages as StreamingMessage[]
			).map((msg) => {
				if (msg.id === messageId || msg.backend_id === messageId) {
					return {
						...msg,
						content: '', // Clear content to show loading state
						displayedContent: '',
						isRegenerating: true,
						shouldAnimate: true // Animate the new content when it arrives
					};
				}
				return msg;
			});
			this.regenerateResponse(
				'',
				message.backend_id || messageId,
				'existing',
				undefined,
				message.id
			);
		}
	}

	async handleGreetingChanged(detail: { index: number; content: string; messageId?: string }) {
		const { content, index, messageId } = detail;

		if (typeof window !== 'undefined' && this.chat?.id) {
			localStorage.setItem(`greeting-variant-${this.chat.id}`, index.toString());
		}

		// Find the message to update
		let targetMessage: StreamingMessage | undefined;

		if (messageId) {
			targetMessage = this.activeStreamingService.messages.find(
				(msg) => msg.id === messageId || msg.backend_id === messageId
			);
		}

		// Fallback: Find the first assistant message (the greeting)
		if (!targetMessage) {
			targetMessage = this.activeStreamingService.messages.find(
				(msg) => msg.sender === 'assistant'
			);
		}

		if (targetMessage) {
			// Update the message in the streaming service
			this.activeStreamingService.messages = (
				this.activeStreamingService.messages as StreamingMessage[]
			).map((msg) =>
				msg.id === targetMessage!.id
					? {
							...msg,
							content,
							displayedContent: content,
							current_variant_index: index,
							_variantChangedAt: Date.now(),
							shouldAnimate: false // Don't animate greeting changes
						}
					: msg
			);

			// Persist selection to backend
			const apiMessageId = targetMessage.backend_id || targetMessage.id;
			if (apiMessageId) {
				try {
					console.log(`💾 Persisting greeting variant ${index} for message ${apiMessageId}`);
					await _apiClient.selectMessageVariant(apiMessageId, {
						variant_index: index
					});
				} catch (_error) {
					console.warn('⚠️ Error persisting first message variant selection:', _error);
				}
			} else {
				console.warn(
					'⚠️ Could not persist greeting variant: No backend ID found for message',
					targetMessage.id
				);
			}
		} else {
			console.warn('⚠️ Could not find message to update greeting variant');
		}
	}
	async loadAgentMode() {
		if (!this.chat?.id) return;
		try {
			const result = await _apiClient.getChatSessionSettings(this.chat.id);
			if (result.isOk()) {
				this.agentMode = (result.value.agent_mode as typeof this.agentMode) || 'disabled';
			} else {
				console.error('Failed to load agent mode:', result.error);
			}
		} catch (_error) {
			console.error('Failed to load agent mode:', _error);
		}
	}

	async saveAgentMode(mode: typeof this.agentMode) {
		if (!this.chat?.id) return;

		const previousMode = this.agentMode;
		this.agentMode = mode;

		try {
			const result = await _apiClient.updateChatSessionSettings(this.chat.id, {
				agent_mode: mode
			});

			if (result.isOk()) {
				const modeLabel =
					mode === 'disabled'
						? 'Off'
						: mode === 'pre_processing'
							? 'Pre-processing'
							: 'Post-processing';
				toast.success(`Context enrichment: ${modeLabel}`);
			} else {
				this.agentMode = previousMode;
				console.error('Failed to save agent mode:', result.error);
				toast.error('Failed to update context enrichment mode');
			}
		} catch (_error) {
			this.agentMode = previousMode;
			console.error('Failed to save agent mode:', _error);
			toast.error('Failed to update context enrichment mode');
		}
	}
}
