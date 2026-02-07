<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { apiClient as _apiClient } from '$lib/api';
	import { untrack } from 'svelte';
	import ChatHeader from './chat-header.svelte';
	import type {
		User,
		ScribeCharacter,
		ScribeChatSession,
		ScribeChatMessage,
		UserPersona,
		LorebookEntry,
		GameState
	} from '$lib/types';
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

	import ChatSetupDialog from './ChatSetupDialog.svelte';
	import RegenerationModal, { type AnalysisMode } from './messages/regeneration-modal.svelte';

	import { getCurrentUser, getIsAuthReady, getIsAuthenticated } from '$lib/auth.svelte';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { UpgradePrompt } from './membership';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import LorebookExtractionDialog from './LorebookExtractionDialog.svelte';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import { ChatController } from '$lib/controllers/chat-controller.svelte';
	import GameStateSidebar from './gamemaster/GameStateSidebar.svelte';
	import { LLMStore } from '$lib/stores/llm.svelte';
	import { SelectedModel } from '$lib/hooks/selected-model.svelte';
	import { getAllAvailableModels } from '$lib/ai/models';

	let {
		user,
		chat: chatProp,
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

	// Use controller.chat as single source of truth - controller has $state internally
	const controller = new ChatController(
		undefined,
		undefined,
		undefined,
		[],
		null,
		''
	);

	// Sync props to controller reactively
	$effect(() => {
		controller.chat = chatProp;
		controller.user = user;
		controller.character = character;
		// initialMessages, initialCursor, and initialChatInputValue are typically for initial load
		// but we can sync them if they change, or just set them once in an untracked block if preferred.
		// For now, let's sync them to ensure the controller has the latest data.
		if (initialMessages) controller.loadedMessagesBatches = [initialMessages];
		if (initialCursor !== undefined) controller.nextCursor = initialCursor;
		if (initialChatInputValue !== undefined) controller.chatInput = initialChatInputValue;
	});

	// Derived chat accessor for convenience
	let chat = $derived(controller.chat);

	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const _selectedPersonaStore = SelectedPersonaStore.fromContext();
	const _settingsStore = SettingsStore.fromContext();
	// const chatHistory = ChatHistory.fromContext();

	// Reactivity for props updates (excluding chat which is already derived from controller.chat)
	$effect(() => {
		controller.user = user;
		controller.character = character;
	});

	// Initialize chat on mount or chat change
	$effect(() => {
		if (chat?.id) {
			controller.initializeChat();
			// controller.fetchSuggestedActions(); // Removed auto-trigger
			controller.loadAgentMode();
		} else {
			// Clear messages if no chat is selected (e.g. home page)
			// This ensures the Overview component is displayed instead of old messages
			controller.activeStreamingService.clearMessages();
		}

		// CRITICAL: Cleanup on component unmount to prevent stale state on navigation
		return () => {
			controller.activeStreamingService.disconnect();
		};
	});

	// --- Model Capabilities ---
	const llmStore = LLMStore.fromContext();
	const selectedChatModel = SelectedModel.fromContext();

	const availableModels = $derived.by(() => {
		const localModels = llmStore.models.filter((m) => m.isLocal && m.downloaded);
		return getAllAvailableModels(localModels);
	});

	const supportsReasoning = $derived.by(() => {
		const modelId = controller.chat?.model_name || selectedChatModel.value;
		if (!modelId) return false;
		const model = availableModels.find((m) => m.id === modelId);
		return model?.supportsReasoning || modelId.toLowerCase().includes('gemini');
	});

	// --- Token Counter State ---
	const tokenCounter = useTokenCounter();
	let showTokenUsage = $state(false);
	let tokenCountTimeout: ReturnType<typeof setTimeout> | null = null;

	$effect(() => {
		if (tokenCountTimeout) {
			clearTimeout(tokenCountTimeout);
		}

		if (controller.chatInput.trim().length > 0) {
			tokenCountTimeout = setTimeout(async () => {
				try {
					const model = await controller.getCurrentChatModel();
					const result = await tokenCounter.countTokensSimple(
						controller.chatInput.trim(),
						model || undefined,
						false
					);
					showTokenUsage = !!(result && result.total > 0);
				} catch (_error) {
					console.error('Token counting failed:', _error);
					showTokenUsage = false;
				}
			}, 3000);
		} else {
			tokenCounter.reset();
			showTokenUsage = false;
		}

		return () => {
			if (tokenCountTimeout) {
				clearTimeout(tokenCountTimeout);
			}
		};
	});

	// --- Chat Config Sidebar State ---
	let isChatConfigOpen = $state(false);
	let availablePersonas = $state<UserPersona[]>([]);
	let currentUserPersona = $state<UserPersona | null>(null);
	let userPersonaName = $derived(currentUserPersona?.name || 'User');

	// --- Game Master Sidebar State ---
	let isGameStatePanelOpen = $state(false);

	function handleToggleGameMasterPanel() {
		isGameStatePanelOpen = !isGameStatePanelOpen;
	}

	// --- Game State Refresh Effect ---
	// When streaming closes and game master mode is enabled, refetch chat to get updated game_state
	let previousStreamStatus = $state<string>('idle');
	$effect(() => {
		const currentStatus = controller.activeStreamingService.connectionStatus;

		// Check if stream just closed and game master mode is enabled
		if (
			previousStreamStatus === 'open' &&
			currentStatus === 'closed' &&
			controller.chat?.game_master_mode_enabled
		) {
			console.log('🎮 Stream closed, refetching game state...');
			// Small delay to allow backend to finish processing game state
			setTimeout(async () => {
				if (!controller.chat?.id) return;
				const result = await _apiClient.getChatById(controller.chat.id);
				if (result.isOk() && result.value.game_state && controller.chat) {
					// Parse game_state if it's a JSON string (backend sends it as string)
					let parsedGameState = result.value.game_state;
					if (typeof parsedGameState === 'string') {
						try {
							parsedGameState = JSON.parse(parsedGameState);
							console.log('🎮 Parsed game_state from JSON string');
						} catch (e) {
							console.error('🎮 Failed to parse game_state JSON:', e);
						}
					}
					controller.chat = { ...controller.chat, game_state: parsedGameState };
					console.log(
						'🎮 Game state updated:',
						JSON.stringify(parsedGameState).substring(0, 200) + '...'
					);
				}
			}, 1500); // 1.5s delay for game state processing
		}
		previousStreamStatus = currentStatus;
	});

	// --- Real-time Game State Sync ---
	$effect(() => {
		const latestState = controller.activeStreamingService.latestGameState;
		if (latestState && controller.chat && controller.chat.game_master_mode_enabled) {
			// Parse game_state if it's a JSON string (backend/SSE may send as string)
			let parsedState: GameState | null = null;
			if (typeof latestState === 'string') {
				try {
					parsedState = JSON.parse(latestState) as GameState;
					console.log('🎮 Parsed real-time game_state from JSON string');
				} catch (e) {
					console.error('🎮 Failed to parse real-time game_state JSON:', e);
				}
			} else {
				// Already an object
				parsedState = latestState as unknown as GameState;
			}
			// Only update if the reference has changed
			if (controller.chat.game_state !== parsedState) {
				console.log(
					'🎮 Real-time Game State Update:',
					typeof parsedState,
					Object.keys(parsedState || {})
				);
				// Create a new chat object to trigger reactivity
				controller.chat = { ...controller.chat, game_state: parsedState };
			}
		}
	});

	// Load available personas
	let hasFetchedPersonas = $state(false);
	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		if (!hasFetchedPersonas && authReady && authenticated) {
			untrack(() => {
				_apiClient.getUserPersonas().then((result) => {
					if (result.isOk()) availablePersonas = result.value;
				});
				// Load user persona logic...
				const currentUser = getCurrentUser();
				if (currentUser?.default_persona_id) {
					_apiClient.getUserPersona(currentUser.default_persona_id).then((res) => {
						if (res.isOk()) currentUserPersona = res.value;
						else if (currentUser.username)
							currentUserPersona = { name: currentUser.username } as UserPersona;
					});
				} else if (currentUser?.username) {
					currentUserPersona = { name: currentUser.username } as UserPersona;
				}
				hasFetchedPersonas = true;
			});
		}
	});

	// --- Lorebook Extraction ---
	let showExtractDialog = $state(false);
	let availableLorebooks = $state<Array<{ id: string; name: string }>>([]);
	let hasFetchedLorebooks = $state(false);
	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		if (!hasFetchedLorebooks && authReady && authenticated) {
			untrack(() => {
				async function loadLorebooks() {
					await lorebookStore.loadLorebooks();
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

	// --- Chat Interface Visibility ---
	let shouldShowChatInterface = $state(false);
	let chatModeStrategy = $derived.by(() => {
		if (!chat || !chat.chat_mode) return null;
		try {
			return createChatModeStrategy(chat.chat_mode);
		} catch {
			return null;
		}
	});

	let placeholderText = $derived.by(() => {
		const strategy = chatModeStrategy;
		if (!strategy) return 'Send a message...';
		return strategy.getMessageInputPlaceholder(character || null);
	});

	$effect(() => {
		const strategy = chatModeStrategy;
		if (!strategy || typeof strategy.shouldShowChatInterface !== 'function') {
			shouldShowChatInterface = false;
			return;
		}
		shouldShowChatInterface = strategy.shouldShowChatInterface(chat || null, character || null);
	});

	let canFetchSuggestions = $derived(shouldShowChatInterface);

	// --- Handlers ---
	function handleOpenExtractDialog() {
		if (!chat?.id) return;
		showExtractDialog = true;
	}

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

	// --- Upgrade Prompt ---
	let showUpgradePrompt = $state(false);

	// --- Template Substitution ---
	function substituteTemplateVariables(text: string, characterName: string): string {
		return controller.substituteTemplateVariables(text, characterName, userPersonaName);
	}
	function handleInputSubmit(e: Event) {
		controller.handleInputSubmit(e);
	}

	// --- Regeneration Handlers ---
	function handleRegenerationConfirm(mode: AnalysisMode, guidance?: string) {
		controller.handleRegenerationConfirm(mode, guidance);
	}

	function handleRegenerationCancel() {
		controller.handleRegenerationCancel();
	}

	// Handle greeting changes from alternate greetings
	async function handleGreetingChanged(detail: {
		index: number;
		content: string;
		messageId?: string;
	}) {
		controller.handleGreetingChanged(detail);
	}

	// --- Message Action Handlers ---
	function handleRetryMessage(messageId: string) {
		controller.handleRetryMessage(messageId);
	}

	function handleEditMessage(messageId: string) {
		controller.handleEditMessage(messageId);
	}

	function handleSaveEditedMessage(messageId: string, newContent: string) {
		controller.handleSaveEditedMessage(messageId, newContent);
	}

	function handleDeleteMessage(messageId: string) {
		controller.handleDeleteMessage(messageId);
	}

	function handlePreviousVariant(messageId: string) {
		controller.handlePreviousVariant(messageId);
	}

	function handleNextVariant(messageId: string) {
		controller.handleNextVariant(messageId);
	}

	function stopGeneration() {
		controller.stopGeneration();
	}

	// Message action handlers
	function handleRetryFailedMessage(messageId: string) {
		controller.handleRetryFailedMessage(messageId);
	}
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
	<ChatHeader
		{chat}
		{readonly}
		onOpenExtractDialog={handleOpenExtractDialog}
		onToggleGameMasterPanel={handleToggleGameMasterPanel}
	/>

	<Messages
		{readonly}
		loading={controller.isLoading}
		messages={controller.messages}
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
		onLoadMore={() => controller.loadMoreMessages()}
		isLoadingMore={controller.isLoadingMore}
		hasMoreMessages={controller.hasMoreMessages}
		suppressAutoScroll={controller.suppressAutoScroll}
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
					console.log('Get Suggestions button clicked!');
					controller.fetchSuggestedActions();
				}}
				disabled={!canFetchSuggestions || controller.isLoadingSuggestions || controller.isLoading}
				class="inline-flex h-10 items-center justify-center gap-2 whitespace-nowrap rounded-md border border-input bg-background px-4 py-2 text-sm font-medium ring-offset-background transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
			>
				{#if controller.isLoadingSuggestions}
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
		{#if controller.dynamicSuggestedActions.length > 0 && !controller.isLoading}
			<div class="mx-auto w-full px-4 pb-2 md:max-w-3xl">
				<SuggestedActions
					{user}
					sendMessage={(msg) => controller.sendMessage(msg)}
					actions={controller.dynamicSuggestedActions}
					onClear={() => {
						controller.dynamicSuggestedActions = [];
					}}
					onEdit={(content) => {
						controller.chatInput = content;
					}}
				/>
			</div>
		{/if}

		<!-- Suggested Actions Error -->
		{#if controller.suggestionsError && !controller.isLoading && !controller.isLoadingSuggestions}
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
								{controller.suggestionsError}
							</p>
							{#if controller.suggestionsRetryable}
								<div class="mt-3 flex gap-2">
									<button
										type="button"
										onclick={() => {
											controller.suggestionsError = null;
											controller.suggestionsRetryable = false;
											controller.fetchSuggestedActions();
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
											controller.suggestionsError = null;
											controller.suggestionsRetryable = false;
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
						bind:value={controller.chatInput}
						isLoading={controller.isLoading}
						{stopGeneration}
						chat={chat}
						chatId={chat?.id}
						supportsReasoning={supportsReasoning}
						placeholder={placeholderText}
						onImpersonate={(response) => {
							controller.chatInput = response;
						}}
						agentMode={controller.agentMode}
						onAgentModeChange={(mode) => controller.saveAgentMode(mode)}
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
					{#if chat?.total_actual_cost || chat?.total_prompt_tokens || chat?.total_completion_tokens}
						{@const sessionCost =
							typeof chat.total_actual_cost === 'number' ? chat.total_actual_cost : 0}
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
			// Update controller.chat to trigger Svelte 5 reactivity
			if (controller.chat) {
				controller.chat = {
					...controller.chat,
					// Update all relevant fields that might have changed
					...event.detail,
					// Ensure game_master_mode_enabled is explicitly handled if present
					game_master_mode_enabled:
						event.detail.game_master_mode_enabled ?? controller.chat.game_master_mode_enabled
				};
			}
		}}
		on:personaChanged={(event) => {
			console.log('Persona changed:', event.detail);
			if (controller.chat) {
				controller.chat = {
					...controller.chat,
					active_custom_persona_id: event.detail.personaId
				};
			}

			// Update currentUserPersona to reflect the change immediately
			if (event.detail.personaId) {
				const persona = availablePersonas.find((p) => p.id === event.detail.personaId);
				if (persona) {
					currentUserPersona = persona;
				}
			} else {
				// Revert to default or username
				const currentUser = getCurrentUser();
				if (currentUser?.default_persona_id) {
					const defaultPersona = availablePersonas.find(
						(p) => p.id === currentUser.default_persona_id
					);
					if (defaultPersona) {
						currentUserPersona = defaultPersona;
					} else if (currentUser?.username) {
						currentUserPersona = { name: currentUser.username } as UserPersona;
					}
				} else if (currentUser?.username) {
					currentUserPersona = { name: currentUser.username } as UserPersona;
				}
			}
		}}
	/>
{/if}

<!-- Game Master Sidebar -->
{#if chat && chat.game_master_mode_enabled}
	<GameStateSidebar
		bind:isOpen={isGameStatePanelOpen}
		gameState={chat.game_state || null}
		isLoading={false}
		sessionId={chat.id}
		onStateUpdate={(newState) => {
			if (controller.chat) {
				controller.chat = { ...controller.chat, game_state: newState };
				// Sync the streaming service's latest state to prevent the sync effect from reverting this change
				controller.activeStreamingService.latestGameState = newState as unknown as Record<
					string,
					unknown
				>;
			}
		}}
	/>
{/if}

<!-- Chat Setup Dialog (Chronicles & Game Master) -->
<ChatSetupDialog
	open={controller.showSetupDialog}
	onConfirm={(options) => controller.handleSetupChoice(options)}
	onOpenChange={(newOpen) => {
		console.log('[Chat] SetupDialog onOpenChange:', newOpen);
		controller.showSetupDialog = newOpen;
	}}
/>

<!-- Regeneration Options Modal -->
<RegenerationModal
	bind:open={controller.showRegenerationModal}
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
		messages={controller.messages.map((msg: ScribeChatMessage, index: number) => ({
			role: msg.message_type.toLowerCase(),
			content: msg.content,
			index
		}))}
		lorebooks={availableLorebooks}
		onOpenChange={(open) => (showExtractDialog = open)}
		onSuccess={handleExtractionSuccess}
	/>
{/if}
