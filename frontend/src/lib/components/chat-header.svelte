<script lang="ts">
	import { useSidebar } from './ui/sidebar';
	import SidebarToggle from './sidebar-toggle.svelte';
	import ModelSelector from './model-selector.svelte';
	import { Badge } from './ui/badge';
	import { Button } from './ui/button';
	import { ScrollText, History } from 'lucide-svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
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

	// Chronicle state management (same pattern as ChatConfigPanel)
	let currentChronicleId = $state<string | null>(null);
	let isLoadingSettings = $state(false);

	// Get chronicle info if this chat belongs to one
	let currentChronicle = $derived.by(() => {
		if (!currentChronicleId) return null;
		return chronicleStore.getChronicleById(currentChronicleId);
	});

	// Check if chat has chronicle ID
	let hasChronicleId = $derived(!!currentChronicleId);

	// Load settings on chat change (same as ChatConfigPanel)
	$effect(() => {
		if (chat?.id) {
			loadChatSettings();
		}
	});

	async function loadChatSettings() {
		if (!chat?.id) return;
		isLoadingSettings = true;
		try {
			const result = await apiClient.getChatSessionSettings(chat.id);
			if (result.isOk()) {
				const settings = result.value;
				// Update currentChronicleId from the fresh backend settings
				// This ensures the UI shows the correct chronicle association from the database
				currentChronicleId = settings.chronicle_id || null;
				console.log('[Chat Header] Loaded settings:', { chronicleId: currentChronicleId });
			} else {
				console.error('[Chat Header] Failed to load chat settings:', result.error);
				// Fallback to chat prop if API fails
				currentChronicleId = chat.chronicle_id || null;
			}
		} catch (error) {
			console.error('[Chat Header] Error loading chat settings:', error);
			// Fallback to chat prop if error occurs
			currentChronicleId = chat.chronicle_id || null;
		} finally {
			isLoadingSettings = false;
		}
	}

	// State for extraction
	let isExtracting = $state(false);

	// Function to trigger event extraction
	async function extractEvents() {
		console.log('[Extract Events] Button clicked', { 
			chatId: chat?.id, 
			currentChronicleId,
			currentChronicle: currentChronicle?.id,
			hasChronicleId,
			isExtracting 
		});

		if (!chat?.id || !currentChronicleId) {
			console.log('[Extract Events] Missing required data', { 
				chatId: chat?.id, 
				currentChronicleId 
			});
			toast.error('Cannot extract events: No active chat session or chronicle');
			return;
		}

		isExtracting = true;
		console.log('[Extract Events] Starting extraction...');
		
		try {
			const result = await apiClient.extractEventsFromChat(currentChronicleId, {
				chat_session_id: chat.id,
				extraction_model: 'gemini-2.5-flash-lite-preview-06-17'
			});

			console.log('[Extract Events] API response:', result);

			if (result.isOk()) {
				const response = result.value;
				toast.success(
					`Successfully extracted ${response.events_extracted} events from this conversation`,
					{
						description: response.events_extracted > 0 
							? 'New events have been added to your chronicle'
							: 'No significant events were found in this conversation'
					}
				);
				
				// Refresh chronicle store to update event counts
				await chronicleStore.refresh();
			} else {
				console.error('[Extract Events] API error:', result.error);
				toast.error('Failed to extract events', {
					description: result.error.message
				});
			}
		} catch (error) {
			console.error('[Extract Events] Exception:', error);
			toast.error('An unexpected error occurred during event extraction');
		} finally {
			isExtracting = false;
			console.log('[Extract Events] Finished');
		}
	}
</script>

<header class="sticky top-0 flex items-center gap-2 bg-background p-2">
	<SidebarToggle />

	{#if isLoadingSettings}
		<Badge variant="secondary" class="gap-1">
			<ScrollText class="h-3 w-3 animate-spin" />
			Loading...
		</Badge>
	{:else if hasChronicleId}
		{#if currentChronicle}
			<Badge variant="secondary" class="gap-1">
				<ScrollText class="h-3 w-3" />
				{currentChronicle.name}
			</Badge>
		{:else}
			<Badge variant="secondary" class="gap-1">
				<ScrollText class="h-3 w-3" />
				Chronicle (Loading...)
			</Badge>
		{/if}
		
		{#if !readonly && chat}
			<Button
				variant="ghost"
				size="sm"
				onclick={extractEvents}
				disabled={isExtracting || isLoadingSettings}
				title="Extract events from this conversation (Chronicle ID: {currentChronicleId})"
				class="gap-1 cursor-pointer hover:bg-accent"
			>
				<History class="h-3 w-3" />
				{isExtracting ? 'Extracting...' : 'Extract Events'}
			</Button>
		{/if}
	{:else if !readonly && chat}
		<!-- Show placeholder when no chronicle is associated -->
		<Button
			variant="outline"
			size="sm"
			disabled
			title="This chat is not associated with a chronicle. Associate with a chronicle to extract events."
			class="gap-1 opacity-60 cursor-not-allowed"
		>
			<History class="h-3 w-3" />
			Extract Events (No Chronicle)
		</Button>
	{/if}

	{#if !readonly && chat}
		<div class="ml-auto">
			<ModelSelector {chat} />
		</div>
	{/if}
</header>
