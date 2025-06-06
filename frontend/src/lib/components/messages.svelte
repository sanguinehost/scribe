<script lang="ts">
	import ThinkingMessage from './messages/thinking-message.svelte';
	import Overview from './messages/overview.svelte';
	import CharacterOverview from './messages/character-overview.svelte';
	import PersonaOverview from './messages/persona-overview.svelte';
	import PersonaEditor from './messages/persona-editor.svelte';
	import SettingsOverview from './messages/settings-overview.svelte';
	import ConsolidatedSettings from './settings/ConsolidatedSettings.svelte';
	import { createEventDispatcher, onMount } from 'svelte';
	import PreviewMessage from './messages/preview-message.svelte';
	import FirstMessage from './messages/first-message.svelte';
	import type { ScribeChatMessage } from '$lib/types';
	import { getLock } from '$lib/hooks/lock';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import * as Tooltip from '$lib/components/ui/tooltip'; // Import Tooltip components

	let containerRef = $state<HTMLDivElement | null>(null);
	let endRef = $state<HTMLDivElement | null>(null);

	let {
		readonly,
		loading,
		messages,
		selectedCharacterId = null,
		character = null
	}: {
		readonly: boolean;
		loading: boolean;
		messages: ScribeChatMessage[];
		selectedCharacterId?: string | null;
		character?: any | null; // Will be properly typed
	} = $props();

	const dispatch = createEventDispatcher();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
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

		console.log('First message detection:', {
			messageId: message.id,
			messageType: message.message_type,
			index,
			hasFirstMessageId,
			isFirstAssistantMessage,
			contentMatchesFirstMes,
			characterFirstMes: character?.first_mes?.substring(0, 50) + '...',
			messageContent: message.content.substring(0, 50) + '...',
			result:
				message.message_type === 'Assistant' &&
				(hasFirstMessageId || isFirstAssistantMessage || contentMatchesFirstMes)
		});

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
	});

	const scrollLock = getLock('messages-scroll');

	$effect(() => {
		if (!(containerRef && endRef)) return;

		const observer = new MutationObserver(() => {
			if (!endRef || scrollLock.locked) return;
			endRef.scrollIntoView({ behavior: 'instant', block: 'end' });
		});

		observer.observe(containerRef, {
			childList: true,
			subtree: true,
			attributes: true,
			characterData: true
		});

		return () => observer.disconnect();
	});
</script>

<Tooltip.Provider>
	<div bind:this={containerRef} class="flex min-w-0 flex-1 flex-col gap-6 overflow-y-scroll pt-4">
		<!-- Settings Panel - shows if store.isVisible is true, regardless of message count -->
		{#if settingsStore.isVisible}
			{#if settingsStore.viewMode === 'overview'}
				<SettingsOverview />
			{:else if settingsStore.viewMode === 'consolidated'}
				<ConsolidatedSettings />
			{/if}
		{/if}

		<!-- Empty Chat Placeholders (only if chat is empty AND settings are NOT visible) -->
		{#if mounted && messages.length === 0 && !settingsStore.isVisible}
			{#if selectedCharacterId}
				<CharacterOverview characterId={selectedCharacterId} />
			{:else if selectedPersonaStore.viewMode === 'creating'}
				<PersonaEditor on:personaCreated={handlePersonaCreated} />
			{:else if selectedPersonaStore.personaId}
				<PersonaOverview personaId={selectedPersonaStore.personaId} />
			{:else}
				<Overview />
			{/if}
		{/if}

		{#each messages as message, index (message.id)}
			{#if isFirstMessage(message, index) && character}
				<FirstMessage
					{message}
					{readonly}
					{loading}
					alternateGreetings={character.alternate_greetings}
					{currentGreetingIndex}
					on:greetingChanged={handleGreetingChanged}
				/>
			{:else}
				<PreviewMessage {message} {readonly} {loading} />
			{/if}
		{/each}

		{#if loading && messages.length > 0 && messages[messages.length - 1].message_type === 'User'}
			<ThinkingMessage />
		{/if}

		<div bind:this={endRef} class="min-h-[24px] min-w-[24px] shrink-0"></div>
	</div>
</Tooltip.Provider>
