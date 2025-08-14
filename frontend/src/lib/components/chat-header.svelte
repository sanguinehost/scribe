<script lang="ts">
	import { useSidebar } from './ui/sidebar';
	import SidebarToggle from './sidebar-toggle.svelte';
	import ModelSelector from './model-selector.svelte';
	import { Badge } from './ui/badge';
	import { Button } from './ui/button';
	import { ScrollText, History, BookOpen, RotateCcw } from 'lucide-svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import type { User, Lorebook } from '$lib/types'; // Updated import path
	import type { ScribeChatSession } from '$lib/types'; // Use Scribe type
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from './ui/dialog';

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

	// Track previous chronicle ID to detect when a new one is assigned
	let previousChronicleId = $state<string | null>(null);

	// Track previous event count to detect when new events are added
	let previousEventCount = $state<number>(0);

	// Load settings on chat change (same as ChatConfigPanel)
	$effect(() => {
		if (chat?.id) {
			loadChatSettings();
		}
	});

	// Refresh chronicle store when a new chronicle is automatically created
	$effect(() => {
		if (currentChronicleId && previousChronicleId === null) {
			console.log(
				'[Chat Header] New chronicle detected, refreshing chronicle store and notifying UI'
			);
			chronicleStore.refresh();

			// Dispatch event to notify other components
			window.dispatchEvent(
				new CustomEvent('chronicle-created', {
					detail: { chronicleId: currentChronicleId }
				})
			);
		}
		previousChronicleId = currentChronicleId;
	});

	// Track event count changes to detect when new events are added
	$effect(() => {
		if (currentChronicle && currentChronicle.event_count > previousEventCount) {
			console.log('[Chat Header] New events detected, notifying UI');

			// Dispatch event to notify other components
			window.dispatchEvent(
				new CustomEvent('chronicle-events-updated', {
					detail: {
						chronicleId: currentChronicleId,
						eventCount: currentChronicle.event_count
					}
				})
			);
		}
		previousEventCount = currentChronicle?.event_count || 0;
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

	// State for re-chronicling
	let isReChronicling = $state(false);

	// State for chronicle creation
	// Note: isCreatingChronicle removed as chronicles are now automatic

	// State for lorebook extraction
	let isExtractingLorebook = $state(false);
	let lorebookExtractionDialogOpen = $state(false);
	let availableLorebooks = $state<Lorebook[]>([]);
	let selectedLorebookId = $state<string | null>(null);
	let isLoadingLorebooks = $state(false);

	// Function to trigger event extraction (legacy method - may not work with current backend)
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
						description:
							response.events_extracted > 0
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

	// Function to re-chronicle events from chat history
	async function reChronicleFromChat() {
		console.log('[Re-Chronicle] Button clicked', {
			chatId: chat?.id,
			currentChronicleId,
			currentChronicle: currentChronicle?.id,
			hasChronicleId,
			isReChronicling
		});

		if (!chat?.id || !currentChronicleId) {
			console.log('[Re-Chronicle] Missing required data', {
				chatId: chat?.id,
				currentChronicleId
			});
			toast.error('Cannot re-chronicle: No active chat session or chronicle');
			return;
		}

		isReChronicling = true;
		console.log('[Re-Chronicle] Starting re-chronicling...');

		try {
			const result = await apiClient.reChronicleFromChat(currentChronicleId, {
				chat_session_id: chat.id,
				purge_existing: true, // Purge existing events by default
				extraction_model: 'gemini-2.5-pro',
				batch_size: 10
			});

			console.log('[Re-Chronicle] API response:', result);

			if (result.isOk()) {
				const response = result.value;
				toast.success(`${response.summary}`, {
					description: `Processed ${response.messages_processed} messages, created ${response.events_created} events${response.events_purged > 0 ? `, purged ${response.events_purged} old events` : ''}`
				});

				// Refresh chronicle store to update event counts
				await chronicleStore.refresh();
			} else {
				console.error('[Re-Chronicle] API error:', result.error);
				toast.error('Failed to re-chronicle events', {
					description: result.error.message
				});
			}
		} catch (error) {
			console.error('[Re-Chronicle] Exception:', error);
			toast.error('An unexpected error occurred during re-chronicling');
		} finally {
			isReChronicling = false;
			console.log('[Re-Chronicle] Finished');
		}
	}

	// Note: Chronicle creation is now automatic through the narrative intelligence system

	// Function to open lorebook extraction dialog
	async function openLorebookExtractionDialog() {
		if (!chat?.id) {
			toast.error('No active chat session');
			return;
		}

		lorebookExtractionDialogOpen = true;
		await loadAvailableLorebooks();
	}

	// Function to load available lorebooks
	async function loadAvailableLorebooks() {
		isLoadingLorebooks = true;
		try {
			const result = await apiClient.getLorebooks();
			if (result.isOk()) {
				availableLorebooks = result.value;
				// Auto-select first lorebook if only one exists
				if (availableLorebooks.length === 1) {
					selectedLorebookId = availableLorebooks[0].id;
				}
			} else {
				console.error('Failed to load lorebooks:', result.error);
				toast.error('Failed to load lorebooks', {
					description: result.error.message
				});
			}
		} catch (error) {
			console.error('Error loading lorebooks:', error);
			toast.error('An unexpected error occurred while loading lorebooks');
		} finally {
			isLoadingLorebooks = false;
		}
	}

	// Function to extract lorebook entries from chat
	async function extractLorebookFromChat() {
		if (!chat?.id || !selectedLorebookId) {
			toast.error('Please select a lorebook');
			return;
		}

		isExtractingLorebook = true;

		try {
			const result = await apiClient.extractLorebookEntriesFromChat(selectedLorebookId, {
				chat_session_id: chat.id,
				extraction_model: 'gemini-2.5-flash-lite-preview-06-17'
			});

			if (result.isOk()) {
				const response = result.value;
				toast.success(`Successfully extracted ${response.entries_extracted} lorebook entries!`, {
					description:
						response.entries_extracted > 0
							? 'New entries have been added to your lorebook'
							: 'No significant world-building information was found'
				});

				// Close dialog on success
				lorebookExtractionDialogOpen = false;
				selectedLorebookId = null;
			} else {
				console.error('Error extracting lorebook entries:', result.error);

				// Clean up error message for user display
				let cleanErrorMessage = result.error.message;
				if (
					result.error.message.includes('PropertyNotFound') ||
					result.error.message.includes('safety filters')
				) {
					cleanErrorMessage =
						'AI safety filters blocked the extraction. Please try again or continue chatting.';
				} else if (result.error.message.includes('Failed to parse stream data')) {
					cleanErrorMessage = 'AI service returned malformed data. Please try again.';
				}

				toast.error(`Could not extract lorebook entries: ${cleanErrorMessage}`);
			}
		} catch (err: any) {
			console.error('Error extracting lorebook entries:', err);

			let cleanErrorMessage = err.message || 'An unexpected error occurred.';
			toast.error(`Could not extract lorebook entries: ${cleanErrorMessage}`);
		} finally {
			isExtractingLorebook = false;
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
				onclick={reChronicleFromChat}
				disabled={isReChronicling || isLoadingSettings || isExtractingLorebook}
				title="Re-chronicle this entire conversation from beginning to end with improved context"
				class="cursor-pointer gap-1 hover:bg-accent"
			>
				<RotateCcw class="h-3 w-3" />
				{isReChronicling ? 'Re-chronicling...' : 'Re-Chronicle'}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={extractEvents}
				disabled={isExtracting || isLoadingSettings || isReChronicling || isExtractingLorebook}
				title="Extract new events from recent messages (Legacy - may not work)"
				class="cursor-pointer gap-1 hover:bg-accent"
			>
				<History class="h-3 w-3" />
				{isExtracting ? 'Extracting...' : 'Extract Events'}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={openLorebookExtractionDialog}
				disabled={isExtractingLorebook || isLoadingSettings || isReChronicling}
				title="Extract world-building information to a lorebook"
				class="cursor-pointer gap-1 hover:bg-accent"
			>
				<BookOpen class="h-3 w-3" />
				{isExtractingLorebook ? 'Extracting...' : 'Extract Lore'}
			</Button>
		{/if}
	{:else if !readonly && chat}
		<!-- Space reserved for future chronicle UI -->
	{/if}

	{#if !readonly && chat}
		<div class="ml-auto">
			<ModelSelector {chat} class="" />
		</div>
	{/if}
</header>

<!-- Lorebook Extraction Dialog -->
<Dialog bind:open={lorebookExtractionDialogOpen}>
	<DialogContent class="sm:max-w-lg">
		<DialogHeader>
			<DialogTitle>Extract Lorebook Entries</DialogTitle>
			<DialogDescription>
				Extract world-building information from this conversation and add it to a lorebook. This
				will analyze character descriptions, locations, lore, items, and other important details.
			</DialogDescription>
		</DialogHeader>

		<div class="space-y-4 py-4">
			{#if isLoadingLorebooks}
				<div class="text-center text-muted-foreground">Loading lorebooks...</div>
			{:else if availableLorebooks.length === 0}
				<div class="text-center text-muted-foreground">
					No lorebooks found. Please create a lorebook first.
				</div>
			{:else}
				<div class="space-y-2">
					<label for="lorebook-select" class="text-sm font-medium">Select Lorebook</label>
					<select
						id="lorebook-select"
						class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
						bind:value={selectedLorebookId}
					>
						<option value={null}>Choose a lorebook...</option>
						{#each availableLorebooks as lorebook}
							<option value={lorebook.id}>{lorebook.name}</option>
						{/each}
					</select>
				</div>

				<div class="rounded-md bg-muted p-3 text-sm text-muted-foreground">
					<strong>What will be extracted:</strong>
					<ul class="mt-2 space-y-1">
						<li>• Character descriptions and backgrounds</li>
						<li>• Locations and settings</li>
						<li>• World lore and mythology</li>
						<li>• Items and artifacts</li>
						<li>• Organizations and factions</li>
						<li>• Important concepts and rules</li>
					</ul>
				</div>
			{/if}
		</div>

		<DialogFooter>
			<Button
				variant="outline"
				onclick={() => {
					lorebookExtractionDialogOpen = false;
					selectedLorebookId = null;
				}}
				disabled={isExtractingLorebook}
			>
				Cancel
			</Button>
			<Button
				onclick={extractLorebookFromChat}
				disabled={isExtractingLorebook || !selectedLorebookId || availableLorebooks.length === 0}
			>
				{isExtractingLorebook ? 'Extracting...' : 'Extract Entries'}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
