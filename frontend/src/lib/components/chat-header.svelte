<script lang="ts">
	import { useSidebar } from './ui/sidebar';
	import SidebarToggle from './sidebar-toggle.svelte';
	import { innerWidth } from 'svelte/reactivity/window';
	import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from './ui/tooltip';
	import { Button } from './ui/button';
	import PlusIcon from './icons/plus.svelte';
	import { goto } from '$app/navigation';
	import ModelSelector from './model-selector.svelte';
	import type { User } from '$lib/types'; // Updated import path
	import type { ScribeChatSession } from '$lib/types'; // Use Scribe type
	import VisibilitySelector from './visibility-selector.svelte';
	import SidebarUserNav from './sidebar-user-nav.svelte'; // Import SidebarUserNav
	import VercelIcon from './icons/vercel.svelte';

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

	{#if !sidebar.open || (innerWidth.current ?? 768) < 768}
		<TooltipProvider>
			<Tooltip>
				<TooltipTrigger>
					{#snippet child({ props })}
						<Button
							{...props}
							variant="outline"
							class="order-2 ml-auto px-2 md:order-1 md:ml-0 md:h-fit md:px-2"
							onclick={() => {
								goto('/', {
									invalidateAll: true
								});
							}}
						>
							<PlusIcon />
							<span class="md:sr-only">New Chat</span>
						</Button>
					{/snippet}
				</TooltipTrigger>
				<TooltipContent>New Chat</TooltipContent>
			</Tooltip>
		</TooltipProvider>
	{/if}

	{#if !readonly}
		<ModelSelector class="order-1 md:order-2" />
	{/if}

	{#if !readonly && chat}
		<VisibilitySelector {chat} class="order-1 md:order-3" />
	{/if}
</header>
