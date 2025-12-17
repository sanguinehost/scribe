<script lang="ts">
	import type { InventoryItem } from '$lib/types';
	import { Package, Box, Home, Landmark } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		inventory?: InventoryItem[] | null;
		inventoryStored?: Record<string, InventoryItem[]> | null;
		assets?: string[] | null;
	}

	let { inventory = [], inventoryStored = {}, assets = [] }: Props = $props();

	// Ensure we always have arrays/objects
	const onPersonItems = $derived(inventory ?? []);
	const storedItems = $derived(inventoryStored ?? {});
	const assetsList = $derived(assets ?? []);

	let activeTab: 'onPerson' | 'stored' | 'assets' = $state('onPerson');

	// Get total item count across all storage
	const totalOnPerson = $derived(onPersonItems.length);
	const totalStored = $derived(
		Object.values(storedItems).reduce((sum, items) => sum + items.length, 0)
	);
	const totalAssets = $derived(assetsList.length);

	// Get rarity color
	function getRarityColor(item: InventoryItem): string {
		const rarity = (item.properties?.rarity as string)?.toLowerCase() || 'common';
		const colors: Record<string, string> = {
			common: 'text-muted-foreground border-border',
			uncommon: 'text-green-500 border-green-600',
			rare: 'text-blue-500 border-blue-600',
			epic: 'text-purple-500 border-purple-600',
			legendary: 'text-amber-500 border-amber-600'
		};
		return colors[rarity] || colors.common;
	}

	// Get category icon
	function getCategoryIcon(category: string | null): string {
		const icons: Record<string, string> = {
			weapon: '⚔️',
			armor: '🛡️',
			consumable: '🧪',
			food: '🍖',
			tool: '🔧',
			key: '🔑',
			treasure: '💎',
			misc: '📦'
		};
		return icons[category?.toLowerCase() || 'misc'] || '📦';
	}
</script>

{#snippet iconSnippet()}
	<Package class="h-4 w-4" />
{/snippet}

{#snippet itemCard(item: InventoryItem)}
	<div
		class="flex items-center gap-2 rounded-lg border bg-muted/50 p-2 transition-colors hover:bg-muted {getRarityColor(
			item
		)}"
	>
		<div class="flex h-8 w-8 items-center justify-center rounded bg-muted text-sm">
			{getCategoryIcon(item.category)}
		</div>
		<div class="min-w-0 flex-1">
			<div class="flex items-center gap-2">
				<span class="truncate text-sm font-medium {getRarityColor(item).split(' ')[0]}">
					{item.name}
				</span>
				{#if item.equipped}
					<span class="rounded bg-green-500/20 px-1 text-[10px] text-green-500">Equipped</span>
				{/if}
			</div>
		</div>
		{#if item.quantity > 1}
			<span class="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
				×{item.quantity}
			</span>
		{/if}
	</div>
{/snippet}

<WidgetBase title="Inventory" icon={iconSnippet}>
	<!-- Tabs: On Person / Stored / Assets -->
	<div class="mb-3 flex gap-1 rounded-lg bg-muted p-1">
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'onPerson'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'onPerson')}
		>
			<Box class="h-3 w-3" />
			On Person ({totalOnPerson})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'stored'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'stored')}
		>
			<Home class="h-3 w-3" />
			Stored ({totalStored})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'assets'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'assets')}
		>
			<Landmark class="h-3 w-3" />
			Assets ({totalAssets})
		</button>
	</div>

	<!-- Content area -->
	<div class="max-h-48 space-y-1.5 overflow-y-auto">
		{#if activeTab === 'onPerson'}
			<!-- On Person items -->
			{#if onPersonItems.length === 0}
				<p class="py-4 text-center text-sm italic text-muted-foreground">No items on person</p>
			{:else}
				{#each onPersonItems as item (item.id)}
					{@render itemCard(item)}
				{/each}
			{/if}
		{:else if activeTab === 'stored'}
			<!-- Stored items by location -->
			{#if Object.keys(storedItems).length === 0}
				<p class="py-4 text-center text-sm italic text-muted-foreground">No stored items</p>
			{:else}
				{#each Object.entries(storedItems) as [location, items]}
					<div class="mb-2">
						<div class="mb-1 flex items-center gap-1 text-xs font-medium text-muted-foreground">
							<Home class="h-3 w-3" />
							{location}
						</div>
						<div class="space-y-1 pl-2">
							{#each items as item (item.id)}
								{@render itemCard(item)}
							{/each}
						</div>
					</div>
				{/each}
			{/if}
		{:else if activeTab === 'assets'}
			<!-- Assets list -->
			{#if assetsList.length === 0}
				<p class="py-4 text-center text-sm italic text-muted-foreground">No major assets</p>
			{:else}
				{#each assetsList as asset, i}
					<div
						class="flex items-center gap-2 rounded-lg border border-border bg-muted/50 p-2 hover:bg-muted"
					>
						<div class="flex h-8 w-8 items-center justify-center rounded bg-muted text-sm">🏠</div>
						<span class="text-sm font-medium">{asset}</span>
					</div>
				{/each}
			{/if}
		{/if}
	</div>
</WidgetBase>
