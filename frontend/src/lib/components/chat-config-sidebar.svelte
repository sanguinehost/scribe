<script lang="ts">
	import { Button } from './ui/button';
	import { createEventDispatcher } from 'svelte';
	import type { ScribeChatSession } from '$lib/types';
	import type { UserPersona } from '$lib/api';
	import ChevronLeft from './icons/chevron-down.svelte';
	import ChevronRight from './icons/chevron-up.svelte';
	import ChatConfigPanel from './settings/ChatConfigPanel.svelte';

	let {
		isOpen = $bindable(false),
		chat,
		availablePersonas = []
	}: {
		isOpen?: boolean;
		chat: ScribeChatSession | null;
		availablePersonas?: UserPersona[];
	} = $props();

	const dispatch = createEventDispatcher();

	function toggleSidebar() {
		isOpen = !isOpen;
	}

	function handleSettingsUpdated(event: CustomEvent) {
		dispatch('settingsUpdated', event.detail);
	}

	function handlePersonaChanged(event: CustomEvent) {
		dispatch('personaChanged', event.detail);
	}
</script>

<!-- Toggle Button (always visible on the right edge) -->
<div class="fixed right-4 top-1/2 z-50 -translate-y-1/2">
	<Button
		variant="ghost"
		size="sm"
		onclick={toggleSidebar}
		class="rounded-l-lg rounded-r-none border-y border-l bg-background shadow-lg hover:bg-accent"
		aria-label={isOpen ? 'Close chat settings' : 'Open chat settings'}
	>
		{#if isOpen}
			<ChevronRight class="h-4 w-4" />
		{:else}
			<ChevronLeft class="h-4 w-4" />
		{/if}
	</Button>
</div>

<!-- Sidebar Panel -->
{#if isOpen}
	<div
		class="fixed right-0 top-0 z-40 h-full w-80 border-l bg-background shadow-xl transition-transform duration-300 ease-in-out"
		style="transform: translateX(0)"
	>
		<div class="flex h-full flex-col">
			<!-- Close Button Header -->
			<div class="flex justify-end border-b p-2">
				<Button variant="ghost" size="sm" onclick={toggleSidebar}>
					<ChevronRight class="h-4 w-4" />
				</Button>
			</div>

			<!-- Chat Config Panel -->
			<div class="flex-1 overflow-hidden">
				<ChatConfigPanel
					{chat}
					{availablePersonas}
					on:settingsUpdated={handleSettingsUpdated}
					on:personaChanged={handlePersonaChanged}
				/>
			</div>
		</div>
	</div>
{/if}

<!-- Backdrop -->
{#if isOpen}
	<div
		class="fixed inset-0 z-30 bg-black/20 md:hidden"
		onclick={toggleSidebar}
		onkeydown={(e) => e.key === 'Escape' && toggleSidebar()}
		role="button"
		tabindex="0"
		aria-label="Close sidebar"
	></div>
{/if}
