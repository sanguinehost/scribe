<script lang="ts">
	import type { InventoryItem } from '$lib/types';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		inventory: InventoryItem[];
	}

	let { inventory = [] }: Props = $props();

	let activeTab: 'all' | 'equipped' | 'consumables' = $state('all');

	// Filtered items based on tab
	let filteredItems = $derived(() => {
		switch (activeTab) {
			case 'equipped':
				return inventory.filter((item) => item.equipped);
			case 'consumables':
				return inventory.filter(
					(item) =>
						item.category?.toLowerCase() === 'consumable' || item.category?.toLowerCase() === 'food'
				);
			default:
				return inventory;
		}
	});

	// Get total weight if items have weight property
	let totalWeight = $derived(
		inventory.reduce((sum, item) => {
			const weight = (item.properties?.weight as number) || 0;
			return sum + weight * item.quantity;
		}, 0)
	);

	// Get rarity color
	function getRarityColor(item: InventoryItem): string {
		const rarity = (item.properties?.rarity as string)?.toLowerCase() || 'common';
		const colors: Record<string, string> = {
			common: 'text-gray-400 border-gray-600',
			uncommon: 'text-green-400 border-green-600',
			rare: 'text-blue-400 border-blue-600',
			epic: 'text-purple-400 border-purple-600',
			legendary: 'text-amber-400 border-amber-600'
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
	<svg
		xmlns="http://www.w3.org/2000/svg"
		class="h-4 w-4"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
	>
		<path d="M4 7V4h16v3"></path>
		<path d="M9 20h6"></path>
		<path d="M12 4v16"></path>
	</svg>
{/snippet}

<WidgetBase title="Inventory" icon={iconSnippet}>
	<!-- Tabs -->
	<div class="mb-3 flex gap-1 rounded-lg bg-gray-800 p-1">
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab === 'all'
				? 'bg-purple-500/30 text-purple-300'
				: 'text-gray-400 hover:text-gray-200'}"
			onclick={() => (activeTab = 'all')}
		>
			All ({inventory.length})
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'equipped'
				? 'bg-purple-500/30 text-purple-300'
				: 'text-gray-400 hover:text-gray-200'}"
			onclick={() => (activeTab = 'equipped')}
		>
			Equipped
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'consumables'
				? 'bg-purple-500/30 text-purple-300'
				: 'text-gray-400 hover:text-gray-200'}"
			onclick={() => (activeTab = 'consumables')}
		>
			Consumables
		</button>
	</div>

	<!-- Item list -->
	<div class="max-h-48 space-y-1.5 overflow-y-auto">
		{#if filteredItems().length === 0}
			<p class="py-4 text-center text-sm italic text-gray-500">No items</p>
		{:else}
			{#each filteredItems() as item (item.id)}
				<div
					class="flex items-center gap-2 rounded-lg border bg-gray-800/50 p-2 transition-colors hover:bg-gray-800 {getRarityColor(
						item
					)}"
				>
					<!-- Icon -->
					<div class="flex h-8 w-8 items-center justify-center rounded bg-gray-700 text-sm">
						{getCategoryIcon(item.category)}
					</div>

					<!-- Info -->
					<div class="min-w-0 flex-1">
						<div class="flex items-center gap-2">
							<span class="truncate text-sm font-medium {getRarityColor(item).split(' ')[0]}">
								{item.name}
							</span>
							{#if item.equipped}
								<span class="rounded bg-green-500/20 px-1 text-[10px] text-green-400">Equipped</span
								>
							{/if}
						</div>
						{#if item.description}
							<p class="truncate text-xs text-gray-500">{item.description}</p>
						{/if}
					</div>

					<!-- Quantity -->
					{#if item.quantity > 1}
						<span class="rounded bg-gray-700 px-1.5 py-0.5 font-mono text-xs text-gray-400">
							×{item.quantity}
						</span>
					{/if}
				</div>
			{/each}
		{/if}
	</div>

	<!-- Weight indicator -->
	{#if totalWeight > 0}
		<div class="mt-3 border-t border-gray-700 pt-2">
			<div class="flex items-center justify-between text-xs text-gray-500">
				<span>Total Weight</span>
				<span class="font-mono">{totalWeight.toFixed(1)} kg</span>
			</div>
		</div>
	{/if}
</WidgetBase>
