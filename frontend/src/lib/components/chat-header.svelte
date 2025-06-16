<script lang="ts">
	import { useSidebar } from './ui/sidebar';
	import SidebarToggle from './sidebar-toggle.svelte';
	import ModelSelector from './model-selector.svelte';
	import type { User } from '$lib/types'; // Updated import path
	import type { ScribeChatSession } from '$lib/types'; // Use Scribe type

	let {
		user,
		chat,
		readonly
	}: {
		user: User | undefined;
		chat: ScribeChatSession | undefined; // Use Scribe type
		readonly: boolean;
	} = $props();

	const sidebar = useSidebar();
</script>

<header class="sticky top-0 flex items-center gap-2 bg-background p-2">
	<SidebarToggle />

	{#if !readonly && chat}
		<ModelSelector {chat} />
	{/if}
</header>
