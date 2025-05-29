<script lang="ts">
	import ThinkingMessage from './messages/thinking-message.svelte';
	import Overview from './messages/overview.svelte';
	import CharacterOverview from './messages/character-overview.svelte';
	import PersonaOverview from './messages/persona-overview.svelte';
	import PersonaEditor from './messages/persona-editor.svelte';
	import SettingsOverview from './messages/settings-overview.svelte';
	import DefaultSettings from './messages/default-settings.svelte';
	import AdvancedSettings from './messages/advanced-settings.svelte';
	import { createEventDispatcher, onMount } from 'svelte';
	import PreviewMessage from './messages/preview-message.svelte';
	import type { ScribeChatMessage } from '$lib/types';
	import { getLock } from '$lib/hooks/lock';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SettingsStore } from '$lib/stores/settings.svelte';

	let containerRef = $state<HTMLDivElement | null>(null);
	let endRef = $state<HTMLDivElement | null>(null);

	let {
		readonly,
		loading,
		messages,
		selectedCharacterId = null
	}: {
		readonly: boolean;
		loading: boolean;
		messages: ScribeChatMessage[];
		selectedCharacterId?: string | null;
	} = $props();

	const dispatch = createEventDispatcher();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const settingsStore = SettingsStore.fromContext();

	function handlePersonaCreated(event: CustomEvent) {
		// Forward the event up to parent components
		dispatch('personaCreated', event.detail);
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

<div bind:this={containerRef} class="flex min-w-0 flex-1 flex-col gap-6 overflow-y-scroll pt-4">
	<!-- Settings Panel - shows if store.isVisible is true, regardless of message count -->
	{#if settingsStore.isVisible}
		{#if settingsStore.viewMode === 'overview'}
			<SettingsOverview />
		{:else if settingsStore.viewMode === 'defaults'}
			<DefaultSettings />
		{:else if settingsStore.viewMode === 'advanced'}
			<AdvancedSettings />
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

	{#each messages as message (message.id)}
		<PreviewMessage {message} {readonly} {loading} />
	{/each}

	{#if loading && messages.length > 0 && messages[messages.length - 1].message_type === 'User'}
		<ThinkingMessage />
	{/if}

	<div bind:this={endRef} class="min-h-[24px] min-w-[24px] shrink-0"></div>
</div>
