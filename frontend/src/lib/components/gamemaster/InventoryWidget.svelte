<script lang="ts">
	import type { InventoryItem } from '$lib/types';
	import { Package } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		inventory?: InventoryItem[] | null;
	}

	let { inventory = [] }: Props = $props();

	// Ensure we always have an array
	const items = inventory ?? [];

	let activeTab: 'all' | 'equipped' | 'consumables' = $state('all');

	// Filtered items based on tab
	let filteredItems = $derived(() => {
		switch (activeTab) {
			case 'equipped':
				return items.filter((item) => item.equipped);
			case 'consumables':
				return items.filter(
					(item) =>
						item.category?.toLowerCase() === 'consumable' || item.category?.toLowerCase() === 'food'
				);
			default:
				return items;
		}
	});

	// Get total weight if items have weight property
	let totalWeight = $derived(
		items.reduce((sum, item) => {
			const weight = (item.properties?.weight as number) || 0;
			return sum + weight * item.quantity;
		}, 0)
	);

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

<WidgetBase title="Inventory" icon={iconSnippet}>
	<!-- Tabs -->
	<div class="bg-muted mb-3 flex gap-1 rounded-lg p-1">
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab === 'all'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'all')}
		>
			All ({items.length})
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'equipped'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'equipped')}
		>
			Equipped
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'consumables'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'consumables')}
		>
			Consumables
		</button>
	</div>

	<!-- Item list -->
	<div class="max-h-48 space-y-1.5 overflow-y-auto">
		{#if filteredItems().length === 0}
			<p class="text-muted-foreground py-4 text-center text-sm italic">No items</p>
		{:else}
			{#each filteredItems() as item (item.id)}
				<div
					class="bg-muted/50 hover:bg-muted flex items-center gap-2 rounded-lg border p-2 transition-colors {getRarityColor(
						item
					)}"
				>
					<!-- Icon -->
					<div class="bg-muted flex h-8 w-8 items-center justify-center rounded text-sm">
						{getCategoryIcon(item.category)}
					</div>

					<!-- Info -->
					<div class="min-w-0 flex-1">
						<div class="flex items-center gap-2">
							<span class="truncate text-sm font-medium {getRarityColor(item).split(' ')[0]}">
								{item.name}
							</span>
							{#if item.equipped}
								<span class="rounded bg-green-500/20 px-1 text-[10px] text-green-500">Equipped</span
								>
							{/if}
						</div>
						{#if item.description}
							<p class="text-muted-foreground truncate text-xs">{item.description}</p>
						{/if}
					</div>

					<!-- Quantity -->
					{#if item.quantity > 1}
						<span class="bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-mono text-xs">
							×{item.quantity}
						</span>
					{/if}
				</div>
			{/each}
		{/if}
	</div>

	<!-- Weight indicator -->
	{#if totalWeight > 0}
		<div class="border-border mt-3 border-t pt-2">
			<div class="text-muted-foreground flex items-center justify-between text-xs">
				<span>Total Weight</span>
				<span class="font-mono">{totalWeight.toFixed(1)} kg</span>
			</div>
		</div>
	{/if}
</WidgetBase>
