<script lang="ts">
	import { useSidebar } from './ui/sidebar';
	import SidebarToggle from './sidebar-toggle.svelte';
	import ModelSelector from './model-selector.svelte';
	import { Badge as BadgeComponent } from './ui/badge';
	import { Button as _ButtonComponent } from './ui/button';
	import { ScrollText, BookMarked } from 'lucide-svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import type { User } from '$lib/types'; // Updated import path
	import type { ScribeChatSession } from '$lib/types'; // Use Scribe type
	import CreditBalance from '$lib/components/credits/CreditBalance.svelte';
	import PurchaseCreditsDialog from '$lib/components/credits/PurchaseCreditsDialog.svelte';
	import { PAYMENT_FEATURES } from '$lib/utils/features';
	import { Button } from '$lib/components/ui/button';

	let {
		user: _user,
		chat,
		readonly,
		onOpenExtractDialog
	}: {
		user: User | undefined;
		chat: ScribeChatSession | undefined; // Use Scribe type
		readonly: boolean;
		onOpenExtractDialog?: () => void;
	} = $props();

	const _sidebar = useSidebar();

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

	// Credit purchase dialog state
	let showPurchaseDialog = $state(false);

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
			const result = await _apiClient.getChatSessionSettings(chat.id);
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
		} catch (_error) {
			console.error('[Chat Header] Error loading chat settings:', _error);
			// Fallback to chat prop if error occurs
			currentChronicleId = chat.chronicle_id || null;
		} finally {
			isLoadingSettings = false;
		}
	}

	// Note: Chronicle creation and all extraction processes are now automatic through the narrative intelligence system

	function handlePurchaseClick() {
		showPurchaseDialog = true;
	}

	function handlePurchaseSuccess() {
		showPurchaseDialog = false;
		toast.success('Purchase completed! Your credits will be available shortly.');
	}
</script>

<header class="sticky top-0 flex items-center gap-2 bg-background p-2">
	<SidebarToggle />

	{#if isLoadingSettings}
		<BadgeComponent variant="secondary" class="gap-1">
			<ScrollText class="h-3 w-3 animate-spin" />
			Loading...
		</BadgeComponent>
	{:else if hasChronicleId}
		{#if currentChronicle}
			<BadgeComponent variant="secondary" class="gap-1">
				<ScrollText class="h-3 w-3" />
				{currentChronicle.name}
			</BadgeComponent>
		{:else}
			<BadgeComponent variant="secondary" class="gap-1">
				<ScrollText class="h-3 w-3" />
				Chronicle (Loading...)
			</BadgeComponent>
		{/if}

		{#if !readonly && chat}
			<!-- Manual extraction buttons removed - system is now fully agent-driven -->
		{/if}
	{:else if !readonly && chat}
		<!-- Space reserved for future chronicle UI -->
	{/if}

	{#if !readonly && chat}
		<div class="ml-auto flex items-center gap-2">
			{#if PAYMENT_FEATURES.credits}
				<CreditBalance
					compact={true}
					showPurchaseButton={true}
					onPurchaseClick={handlePurchaseClick}
				/>
			{/if}
			<Button variant="outline" size="sm" onclick={() => onOpenExtractDialog?.()} class="gap-1.5">
				<BookMarked class="h-4 w-4" />
				Extract
			</Button>
			<ModelSelector {chat} class="" />
		</div>
	{/if}
</header>

<!-- Purchase Credits Dialog -->
{#if PAYMENT_FEATURES.credits}
	<PurchaseCreditsDialog
		bind:open={showPurchaseDialog}
		on:close={() => (showPurchaseDialog = false)}
		on:purchaseSuccess={handlePurchaseSuccess}
	/>
{/if}
