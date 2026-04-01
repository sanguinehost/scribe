<script lang="ts">
	import { Button as ButtonComponent } from './ui/button';
	import { createEventDispatcher } from 'svelte';
	import type { ScribeChatSession } from '$lib/types';
	import type { UserPersona } from '$lib/types';
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

	function handleSettingsUpdated(_event: CustomEvent) {
		dispatch('settingsUpdated', _event.detail);
	}

	function handlePersonaChanged(_event: CustomEvent) {
		dispatch('personaChanged', _event.detail);
	}
</script>

<!-- Toggle Button (always visible on the right edge) -->
<div class="fixed right-0 top-1/2 z-40 -translate-y-1/2">
	<ButtonComponent
		variant="outline"
		size="sm"
		onclick={toggleSidebar}
		class="h-12 w-6 rounded-l-xl rounded-r-none border-y border-l border-border/40 bg-card/50 px-1 shadow-lg backdrop-blur-md transition-all hover:w-8 hover:bg-accent/50"
		aria-label={isOpen ? 'Close chat settings' : 'Open chat settings'}
	>
		{#if isOpen}
			<ChevronRight class="h-4 w-4 shrink-0 text-muted-foreground" />
		{:else}
			<ChevronLeft class="h-4 w-4 shrink-0 text-muted-foreground" />
		{/if}
	</ButtonComponent>
</div>

<!-- Sidebar Panel -->
{#if isOpen}
	<div
		class="fixed right-0 top-0 z-50 h-full w-80 border-l border-border/40 bg-card/60 shadow-2xl backdrop-blur-xl transition-transform duration-300 ease-out md:w-96"
	>
		<div class="flex h-full flex-col">
			<!-- Close Button Header -->
			<div class="flex items-center justify-between border-b border-border/40 bg-muted/20 px-4 py-3">
				<h2 class="text-sm font-semibold tracking-tight text-foreground">Chat Configuration</h2>
				<ButtonComponent variant="ghost" size="icon" class="h-8 w-8 rounded-full text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground" onclick={toggleSidebar}>
					<ChevronRight class="h-4 w-4" />
				</ButtonComponent>
			</div>

			<!-- Chat Config Panel -->
			<div class="flex-1 overflow-hidden">
				<ChatConfigPanel
					{chat}
					{availablePersonas}
					compact={true}
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
		class="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm md:hidden"
		onclick={toggleSidebar}
		onkeydown={(e) => e.key === 'Escape' && toggleSidebar()}
		role="button"
		tabindex="0"
		aria-label="Close sidebar"
	></div>
{/if}
