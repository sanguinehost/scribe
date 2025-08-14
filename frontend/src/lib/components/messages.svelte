<script lang="ts">
	import ThinkingMessage from './messages/thinking-message.svelte';
	import Overview from './messages/overview.svelte';
	import CharacterOverview from './messages/character-overview.svelte';
	import PersonaOverview from './messages/persona-overview.svelte';
	import PersonaEditor from './messages/persona-editor.svelte';
	import LorebookOverview from './messages/lorebook-overview.svelte';
	import LorebookDetailOverview from './messages/lorebook-detail-overview.svelte';
	import ChronicleOverview from './messages/chronicle-overview.svelte';
	import ChroniclesListOverview from './messages/chronicles-list-overview.svelte';
	import ChronicleCreation from './messages/chronicle-creation.svelte';
	import Settings from './settings/Settings.svelte';
	import { onMount } from 'svelte';
	import Message from './messages/message.svelte';
	import FirstMessage from './messages/first-message.svelte';
	import type { ScribeChatMessage, User, ScribeChatSession } from '$lib/types';
	import { getLock } from '$lib/hooks/lock';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SelectedLorebookStore } from '$lib/stores/selected-lorebook.svelte';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { fly, fade } from 'svelte/transition';
	import { quintOut } from 'svelte/easing';
	import * as Tooltip from '$lib/components/ui/tooltip'; // Import Tooltip components
	import { infiniteScroll } from '$lib/actions/infinite-scroll';
	import { Loader2 } from 'lucide-svelte';

	let containerRef = $state<HTMLDivElement | null>(null);
	let endRef = $state<HTMLDivElement | null>(null);

	let {
		readonly,
		loading,
		messages,
		selectedCharacterId = null,
		character = null,
		chat = undefined,
		user = undefined, // Add user prop here
		onRetryMessage,
		onRetryFailedMessage,
		onEditMessage,
		onSaveEditedMessage,
		onDeleteMessage,
		onPreviousVariant,
		onNextVariant,
		messageVariants,
		currentVariantIndex,
		onGreetingChanged,
		onLoadMore,
		isLoadingMore = false,
		hasMoreMessages = false,
		suppressAutoScroll = false
	}: {
		readonly: boolean;
		loading: boolean;
		messages: ScribeChatMessage[];
		selectedCharacterId?: string | null;
		character?: any | null; // Will be properly typed
		chat?: ScribeChatSession | undefined;
		user?: User | undefined; // Type for user prop
		onRetryMessage?: (messageId: string) => void;
		onRetryFailedMessage?: (messageId: string) => void;
		onEditMessage?: (messageId: string) => void;
		onSaveEditedMessage?: (messageId: string, newContent: string) => void;
		onDeleteMessage?: (messageId: string) => void;
		onPreviousVariant?: (messageId: string) => void;
		onNextVariant?: (messageId: string) => void;
		messageVariants?: Map<string, { content: string; timestamp: string }[]>;
		currentVariantIndex?: Map<string, number>;
		onGreetingChanged?: (detail: { index: number; content: string }) => void;
		onLoadMore?: () => void;
		isLoadingMore?: boolean;
		hasMoreMessages?: boolean;
		suppressAutoScroll?: boolean;
	} = $props();

	// Track message count for performance optimization
	let lastMessageCount = 0;
	
	$effect(() => {
		if (!loading && messages.length !== lastMessageCount) {
			lastMessageCount = messages.length;
		}
	});

	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const selectedLorebookStore = SelectedLorebookStore.fromContext();
	const selectedChronicleStore = SelectedChronicleStore.fromContext();
	const settingsStore = SettingsStore.fromContext();

	// State for managing alternate greetings
	let currentGreetingIndex = $state(0);

	// Function to detect if a message is the first message from a character
	function isFirstMessage(message: ScribeChatMessage, index: number): boolean {
		// Check if it's an Assistant message and either:
		// 1. Has the expected first-message ID pattern, OR
		// 2. Is the first Assistant message in the conversation, OR
		// 3. Content matches the character's first_mes
		const hasFirstMessageId = message.id.startsWith('first-message-');
		const isFirstAssistantMessage = message.message_type === 'Assistant' && index === 0;
		const contentMatchesFirstMes = character && message.content === character.first_mes;

		// Debug logging removed for production

		return (
			message.message_type === 'Assistant' &&
			(hasFirstMessageId || isFirstAssistantMessage || contentMatchesFirstMes)
		);
	}

	function handleGreetingChanged(event: CustomEvent) {
		const { index, content } = event.detail;
		currentGreetingIndex = index;
		onGreetingChanged?.({ index, content });
	}

	let mounted = $state(false);
	onMount(() => {
		mounted = true;

		// Listen for lorebook events from the overview components
		const handleSelectLorebook = (event: CustomEvent) => {
			selectedLorebookStore.selectLorebook(event.detail.lorebookId);
		};

		const handleEditLorebook = (event: CustomEvent) => {
			selectedLorebookStore.selectLorebook(event.detail.lorebookId);
		};

		const handleBackToLorebookList = () => {
			selectedLorebookStore.showList();
		};

		document.addEventListener('selectLorebook', handleSelectLorebook as EventListener);
		document.addEventListener('editLorebook', handleEditLorebook as EventListener);
		document.addEventListener('backToLorebookList', handleBackToLorebookList);

		return () => {
			document.removeEventListener('selectLorebook', handleSelectLorebook as EventListener);
			document.removeEventListener('editLorebook', handleEditLorebook as EventListener);
			document.removeEventListener('backToLorebookList', handleBackToLorebookList);
		};
	});

	const scrollLock = getLock('messages-scroll');

	$effect(() => {
		if (!(containerRef && endRef)) return;

		const observer = new MutationObserver((mutations) => {
			if (!endRef || scrollLock.locked) return;
			
			// Don't auto-scroll during streaming to allow user to freely scroll
			const hasAnimatingMessages = messages.some(m => m.loading || (m as any).isAnimating);
			if (hasAnimatingMessages) return;
			
			// Don't auto-scroll during infinite scroll loading or when suppressed
			if (isLoadingMore || suppressAutoScroll) return;
			
			// Only scroll for meaningful content changes, not button state changes
			const shouldScroll = mutations.some(mutation => {
				// Allow childList changes (new messages)
				if (mutation.type === 'childList') return true;
				
				// Allow text content changes (message content updates)
				if (mutation.type === 'characterData') return true;
				
				// For attribute changes, only scroll if it's not a UI state change
				if (mutation.type === 'attributes') {
					const target = mutation.target as Element;
					// Ignore class changes on buttons and their children
					if (target.tagName === 'BUTTON' || target.closest('button')) {
						return false;
					}
					// Ignore class changes on avatar elements (they change during loading)
					if (target.id?.startsWith('bits-') || target.classList?.contains('size-8')) {
						return false;
					}
					// Ignore class changes on elements with message action classes
					if (target.classList?.contains('opacity-0') || 
						target.classList?.contains('opacity-100') ||
						target.closest('.group')) {
						return false;
					}
					// Ignore attribute changes on interactive UI elements
					if (target.closest('[data-role]') || target.closest('.relative')) {
						return false;
					}
					return true;
				}
				
				return false;
			});
			
			// Only auto-scroll if we have actual chat messages and meaningful changes occurred
			if (shouldScroll && messages.length > 0) {
				endRef.scrollIntoView({ behavior: 'instant', block: 'end' });
			}
		});

		observer.observe(containerRef, {
			childList: true,
			subtree: true,
			attributes: true,
			characterData: true
		});

		return () => observer.disconnect();
	});

	// Scroll to top when showing character overview, settings, or other empty states
	$effect(() => {
		if (!containerRef || !mounted) return;

		// If we're showing empty state content (no messages), scroll to top
		// This triggers when view changes (character selection, settings, etc.)
		if (messages.length === 0) {
			// Use a small timeout to ensure the content has rendered first
			setTimeout(() => {
				if (containerRef) {
					containerRef.scrollTo({ top: 0, behavior: 'smooth' });
				}
			}, 100);
		}
	});

	// Also scroll to top when starting fresh chats (with only initial message)
	$effect(() => {
		if (!containerRef || !mounted) return;

		// For truly new chats with just a greeting message, scroll to top
		// instead of bottom to show the character info and start of conversation
		const isNewChat = chat && new Date().getTime() - new Date(chat.created_at).getTime() < 5000; // Less than 5 seconds old
		if (messages.length === 1 && messages[0]?.message_type === 'Assistant' && isNewChat) {
			setTimeout(() => {
				if (containerRef) {
					containerRef.scrollTo({ top: 0, behavior: 'smooth' });
				}
			}, 100);
		}
	});

	// Scroll to bottom when loading existing chats with messages
	$effect(() => {
		if (!containerRef || !mounted || !endRef) return;

		// For existing chats with messages, scroll to bottom (most recent message)
		// Only on initial load (when message count is 20 or less = initial batch)
		const isNewChat = chat && new Date().getTime() - new Date(chat.created_at).getTime() < 5000;
		const isInitialLoad = messages.length <= 20;
		if (messages.length > 0 && !isNewChat && !isLoadingMore && !suppressAutoScroll && isInitialLoad) {
			setTimeout(() => {
				if (endRef) {
					endRef.scrollIntoView({ behavior: 'smooth' });
				}
			}, 100);
		}
	});
</script>

<Tooltip.Provider>
	<div 
		bind:this={containerRef} 
		class="flex min-w-0 flex-1 flex-col gap-6 overflow-y-scroll {(mounted && messages.length === 0) || settingsStore.isVisible ? '' : 'pt-4'}"
		data-messages-container
		use:infiniteScroll={{ 
			threshold: 200, 
			debounce: 300
		}}
	>
		<!-- Settings Panel - shows if store.isVisible is true, regardless of message count -->
		{#if settingsStore.isVisible || settingsStore.isTransitioning}
			<div class="relative flex-1 flex items-center justify-center">
				<div 
					class="w-full settings-content-view" 
					class:active={settingsStore.isVisible}
					class:inactive={!settingsStore.isVisible}
				>
					<div 
						class="settings-view-content"
						in:fade={{ duration: 400 }} 
						out:fade={{ duration: 300 }}
					>
						<Settings />
					</div>
				</div>
			</div>
		{/if}

		<!-- Empty Chat Placeholders (only if chat is empty AND settings are NOT visible AND not transitioning) -->
		{#if mounted && messages.length === 0 && !settingsStore.isVisible && !settingsStore.isTransitioning}
			<div class="relative flex-1 flex">
				<!-- Apply same smooth transition approach as sidebar -->
				<div
					class="main-content-view"
					class:active={selectedCharacterId}
					class:inactive={!selectedCharacterId}
				>
					{#if selectedCharacterId}
						<CharacterOverview characterId={selectedCharacterId} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedChronicleStore.selectedChronicleId &&
						!selectedCharacterId}
					class:inactive={!selectedChronicleStore.selectedChronicleId ||
						selectedCharacterId}
				>
					{#if selectedChronicleStore.selectedChronicleId && !selectedCharacterId}
						<ChronicleOverview chronicleId={selectedChronicleStore.selectedChronicleId} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedChronicleStore.isShowingList &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedCharacterId}
					class:inactive={!selectedChronicleStore.isShowingList ||
						selectedChronicleStore.selectedChronicleId ||
						selectedCharacterId}
				>
					{#if selectedChronicleStore.isShowingList && !selectedChronicleStore.selectedChronicleId && !selectedCharacterId}
						<ChroniclesListOverview />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedChronicleStore.isCreating &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedCharacterId}
					class:inactive={!selectedChronicleStore.isCreating ||
						selectedChronicleStore.selectedChronicleId ||
						selectedCharacterId}
				>
					{#if selectedChronicleStore.isCreating && !selectedChronicleStore.selectedChronicleId && !selectedCharacterId}
						<ChronicleCreation />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedPersonaStore.viewMode === 'creating' &&
						!selectedCharacterId &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedChronicleStore.isShowingList &&
						!selectedChronicleStore.isCreating}
					class:inactive={selectedPersonaStore.viewMode !== 'creating' ||
						selectedCharacterId ||
						selectedChronicleStore.selectedChronicleId ||
						selectedChronicleStore.isShowingList ||
						selectedChronicleStore.isCreating}
				>
					{#if selectedPersonaStore.viewMode === 'creating' && !selectedCharacterId && !selectedChronicleStore.selectedChronicleId && !selectedChronicleStore.isShowingList && !selectedChronicleStore.isCreating}
						<PersonaEditor />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating' &&
						!selectedCharacterId &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedChronicleStore.isShowingList &&
						!selectedChronicleStore.isCreating}
					class:inactive={!selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating' ||
						selectedCharacterId ||
						selectedChronicleStore.selectedChronicleId ||
						selectedChronicleStore.isShowingList ||
						selectedChronicleStore.isCreating}
				>
					{#if selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating' && !selectedCharacterId && !selectedChronicleStore.selectedChronicleId && !selectedChronicleStore.isShowingList && !selectedChronicleStore.isCreating}
						<PersonaOverview personaId={selectedPersonaStore.personaId} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedLorebookStore.viewMode === 'detail' &&
						selectedLorebookStore.lorebookId &&
						!selectedCharacterId &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedChronicleStore.isShowingList &&
						!selectedChronicleStore.isCreating &&
						!selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating'}
					class:inactive={selectedLorebookStore.viewMode !== 'detail' ||
						!selectedLorebookStore.lorebookId ||
						selectedCharacterId ||
						selectedChronicleStore.selectedChronicleId ||
						selectedChronicleStore.isShowingList ||
						selectedChronicleStore.isCreating ||
						selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating'}
				>
					{#if selectedLorebookStore.viewMode === 'detail' && selectedLorebookStore.lorebookId && !selectedCharacterId && !selectedChronicleStore.selectedChronicleId && !selectedChronicleStore.isShowingList && !selectedChronicleStore.isCreating && !selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating'}
						<LorebookDetailOverview lorebookId={selectedLorebookStore.lorebookId} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedLorebookStore.viewMode === 'list' &&
						!selectedCharacterId &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedChronicleStore.isShowingList &&
						!selectedChronicleStore.isCreating &&
						!selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating'}
					class:inactive={selectedLorebookStore.viewMode !== 'list' ||
						selectedCharacterId ||
						selectedChronicleStore.selectedChronicleId ||
						selectedChronicleStore.isShowingList ||
						selectedChronicleStore.isCreating ||
						selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating'}
				>
					{#if selectedLorebookStore.viewMode === 'list' && !selectedCharacterId && !selectedChronicleStore.selectedChronicleId && !selectedChronicleStore.isShowingList && !selectedChronicleStore.isCreating && !selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating'}
						<LorebookOverview />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={!selectedCharacterId &&
						!selectedChronicleStore.selectedChronicleId &&
						!selectedChronicleStore.isShowingList &&
						!selectedChronicleStore.isCreating &&
						!selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating' &&
						selectedLorebookStore.viewMode === 'none'}
					class:inactive={selectedCharacterId ||
						selectedChronicleStore.selectedChronicleId ||
						selectedChronicleStore.isShowingList ||
						selectedChronicleStore.isCreating ||
						selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating' ||
						selectedLorebookStore.viewMode !== 'none'}
				>
					{#if !selectedCharacterId && !selectedChronicleStore.selectedChronicleId && !selectedChronicleStore.isShowingList && !selectedChronicleStore.isCreating && !selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating' && selectedLorebookStore.viewMode === 'none'}
						<Overview />
					{/if}
				</div>
			</div>
		{/if}

		<!-- Loading indicator for loading more messages -->
		{#if isLoadingMore && hasMoreMessages}
			<div class="flex justify-center py-4">
				<div class="flex items-center gap-2 text-muted-foreground">
					<Loader2 class="h-4 w-4 animate-spin" />
					<span class="text-sm">Loading older messages...</span>
				</div>
			</div>
		{/if}

		{#each messages as message, index (message.id)}
			{#if isFirstMessage(message, index) && character}
				<FirstMessage
					{message}
					{readonly}
					loading={false}
					alternateGreetings={character.alternate_greetings}
					{currentGreetingIndex}
					on:greetingChanged={handleGreetingChanged}
					{character}
					{user}
				/>
			{:else}
				{@const variants = messageVariants?.get(message.id)}
				{@const currentIndex = currentVariantIndex?.get(message.id) ?? ((variants?.length ?? 0) > 0 ? (variants?.length ?? 1) - 1 : 0)}
				{@const hasVariants = (variants?.length ?? 0) > 0 || currentIndex > 0}
				{@const variantInfo = hasVariants ? { current: currentIndex, total: (variants?.length ?? 1) - 1 } : null}
				
				<Message 
					{message} 
					{readonly}
					{loading}
					{user}
					{character}
					{chat}
					{hasVariants}
					{variantInfo}
					{onRetryMessage}
					{onRetryFailedMessage}
					{onEditMessage}
					{onSaveEditedMessage}
					{onDeleteMessage}
					{onPreviousVariant}
					{onNextVariant}
				/>
			{/if}
		{/each}

		{#if loading && messages.length > 0 && messages[messages.length - 1].message_type === 'User'}
			<ThinkingMessage />
		{/if}

		<div bind:this={endRef} class="min-h-[24px] min-w-[24px] shrink-0"></div>
	</div>
</Tooltip.Provider>

<style>
	.main-content-view {
		position: absolute;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		transition: opacity 600ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
		pointer-events: none;
		opacity: 0;
	}

	.main-content-view.active {
		pointer-events: auto;
		opacity: 1;
	}

	.main-content-view.inactive {
		pointer-events: none;
		opacity: 0;
	}

	.settings-content-view {
		transition: opacity 600ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
		pointer-events: none;
		opacity: 0;
	}

	.settings-content-view.active {
		pointer-events: auto;
		opacity: 1;
	}

	.settings-content-view.inactive {
		pointer-events: none;
		opacity: 0;
	}

	.settings-view-content {
		width: 100%;
		max-width: 100%;
	}
</style>
