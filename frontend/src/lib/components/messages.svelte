<script lang="ts">
	import ThinkingMessage from './messages/thinking-message.svelte';
	import Overview from './messages/overview.svelte';
	import CharacterOverview from './messages/character-overview.svelte';
	import PersonaOverview from './messages/persona-overview.svelte';
	import PersonaEditor from './messages/persona-editor.svelte';
	import SettingsOverview from './messages/settings-overview.svelte';
	import LorebookOverview from './messages/lorebook-overview.svelte';
	import LorebookDetailOverview from './messages/lorebook-detail-overview.svelte';
	import ConsolidatedSettings from './settings/ConsolidatedSettings.svelte';
	import { createEventDispatcher, onMount } from 'svelte';
	import PreviewMessage from './messages/preview-message.svelte';
	import FirstMessage from './messages/first-message.svelte';
	import type { ScribeChatMessage, User } from '$lib/types';
	import { getLock } from '$lib/hooks/lock';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SelectedLorebookStore } from '$lib/stores/selected-lorebook.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { fly, fade } from 'svelte/transition';
	import { quintOut } from 'svelte/easing';
	import * as Tooltip from '$lib/components/ui/tooltip'; // Import Tooltip components

	let containerRef = $state<HTMLDivElement | null>(null);
	let endRef = $state<HTMLDivElement | null>(null);

	let {
		readonly,
		loading,
		messages,
		selectedCharacterId = null,
		character = null,
		user = undefined // Add user prop here
	}: {
		readonly: boolean;
		loading: boolean;
		messages: ScribeChatMessage[];
		selectedCharacterId?: string | null;
		character?: any | null; // Will be properly typed
		user?: User | undefined; // Type for user prop
	} = $props();

	const dispatch = createEventDispatcher();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const selectedLorebookStore = SelectedLorebookStore.fromContext();
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

	function handlePersonaCreated(event: CustomEvent) {
		// Forward the event up to parent components
		dispatch('personaCreated', event.detail);
	}

	function handleGreetingChanged(event: CustomEvent) {
		const { index, content } = event.detail;
		currentGreetingIndex = index;
		dispatch('greetingChanged', { index, content });
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

		const observer = new MutationObserver(() => {
			if (!endRef || scrollLock.locked) return;
			// Only auto-scroll if we have actual chat messages
			// Don't scroll for character overviews, settings, or empty states
			if (messages.length > 0) {
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

		// For new chats with just a greeting message, scroll to top
		// instead of bottom to show the character info and start of conversation
		if (messages.length === 1 && messages[0]?.message_type === 'Assistant') {
			setTimeout(() => {
				if (containerRef) {
					containerRef.scrollTo({ top: 0, behavior: 'smooth' });
				}
			}, 100);
		}
	});
</script>

<Tooltip.Provider>
	<div bind:this={containerRef} class="flex min-w-0 flex-1 flex-col gap-6 overflow-y-scroll pt-4">
		<!-- Settings Panel - shows if store.isVisible is true, regardless of message count -->
		{#if settingsStore.isVisible}
			<div class="relative">
				{#key settingsStore.viewMode}
					{#if settingsStore.viewMode === 'overview'}
						<div in:fly={{ y: 30, duration: 400, easing: quintOut }} out:fade={{ duration: 200 }}>
							<SettingsOverview />
						</div>
					{:else if settingsStore.viewMode === 'consolidated'}
						<div in:fly={{ y: 30, duration: 400, easing: quintOut }} out:fade={{ duration: 200 }}>
							<ConsolidatedSettings />
						</div>
					{/if}
				{/key}
			</div>
		{/if}

		<!-- Empty Chat Placeholders (only if chat is empty AND settings are NOT visible) -->
		{#if mounted && messages.length === 0 && !settingsStore.isVisible}
			<div class="relative">
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
					class:active={selectedPersonaStore.viewMode === 'creating'}
					class:inactive={selectedPersonaStore.viewMode !== 'creating'}
				>
					{#if selectedPersonaStore.viewMode === 'creating'}
						<PersonaEditor on:personaCreated={handlePersonaCreated} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating'}
					class:inactive={!selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating'}
				>
					{#if selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating'}
						<PersonaOverview personaId={selectedPersonaStore.personaId} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedLorebookStore.viewMode === 'detail' &&
						selectedLorebookStore.lorebookId &&
						!selectedCharacterId &&
						!selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating'}
					class:inactive={selectedLorebookStore.viewMode !== 'detail' ||
						!selectedLorebookStore.lorebookId ||
						selectedCharacterId ||
						selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating'}
				>
					{#if selectedLorebookStore.viewMode === 'detail' && selectedLorebookStore.lorebookId && !selectedCharacterId && !selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating'}
						<LorebookDetailOverview lorebookId={selectedLorebookStore.lorebookId} />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={selectedLorebookStore.viewMode === 'list' &&
						!selectedCharacterId &&
						!selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating'}
					class:inactive={selectedLorebookStore.viewMode !== 'list' ||
						selectedCharacterId ||
						selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating'}
				>
					{#if selectedLorebookStore.viewMode === 'list' && !selectedCharacterId && !selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating'}
						<LorebookOverview />
					{/if}
				</div>
				<div
					class="main-content-view"
					class:active={!selectedCharacterId &&
						!selectedPersonaStore.personaId &&
						selectedPersonaStore.viewMode !== 'creating' &&
						selectedLorebookStore.viewMode === 'none'}
					class:inactive={selectedCharacterId ||
						selectedPersonaStore.personaId ||
						selectedPersonaStore.viewMode === 'creating' ||
						selectedLorebookStore.viewMode !== 'none'}
				>
					{#if !selectedCharacterId && !selectedPersonaStore.personaId && selectedPersonaStore.viewMode !== 'creating' && selectedLorebookStore.viewMode === 'none'}
						<Overview />
					{/if}
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
				<PreviewMessage {message} {readonly} {loading} {user} {character} />
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
</style>
