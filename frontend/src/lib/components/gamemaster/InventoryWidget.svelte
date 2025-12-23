<script lang="ts">
	import type { InventoryItem, GameState } from '$lib/types';
	import { Package, Box, Home, Landmark, Edit2, Save, X, Plus, Trash2 } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { Textarea } from '../ui/textarea';

	interface Props {
		inventory?: InventoryItem[] | null;
		inventoryStored?: Record<string, InventoryItem[]> | null;
		assets?: string[] | null;
		onUpdate?: (updates: Partial<GameState>) => void;
	}

	let { inventory = [], inventoryStored = {}, assets = [], onUpdate }: Props = $props();

	// Ensure we always have arrays/objects
	const onPersonItems = $derived(inventory ?? []);
	const storedItems = $derived(inventoryStored ?? {});
	const assetsList = $derived(assets ?? []);

	let activeTab: 'onPerson' | 'stored' | 'assets' = $state('onPerson');

	let isEditing = $state(false);
	let editInventory = $state<InventoryItem[]>([]);
	let editStored = $state<Record<string, InventoryItem[]>>({});
	let editAssets = $state<string[]>([]);

	function startEditing() {
		editInventory = inventory ? JSON.parse(JSON.stringify(inventory)) : [];
		editStored = inventoryStored ? JSON.parse(JSON.stringify(inventoryStored)) : {};
		editAssets = assets ? [...assets] : [];
		isEditing = true;
	}

	function save() {
		if (onUpdate) {
			onUpdate({
				inventory: editInventory,
				inventory_stored: editStored,
				assets: editAssets
			});
		}
		isEditing = false;
	}

	function cancel() {
		isEditing = false;
	}

	function addItem(location: 'onPerson' | string) {
		const newItem: InventoryItem = {
			id: crypto.randomUUID(),
			name: 'New Item',
			quantity: 1,
			description: '',
			category: 'misc',
			equipped: false,
			properties: { rarity: 'common' }
		};

		if (location === 'onPerson') {
			editInventory.push(newItem);
		} else {
			if (!editStored[location]) editStored[location] = [];
			editStored[location].push(newItem);
		}
	}

	function removeItem(location: 'onPerson' | string, index: number) {
		if (location === 'onPerson') {
			editInventory = editInventory.filter((_, i) => i !== index);
		} else {
			if (editStored[location]) {
				editStored[location] = editStored[location].filter((_, i) => i !== index);
			}
		}
	}

	function addStorageLocation() {
		const name = `Storage ${Object.keys(editStored).length + 1}`;
		editStored[name] = [];
	}

	function removeStorageLocation(name: string) {
		const newStored = { ...editStored };
		delete newStored[name];
		editStored = newStored;
	}

	function addAsset() {
		editAssets.push('New Asset');
	}

	function removeAsset(index: number) {
		editAssets = editAssets.filter((_, i) => i !== index);
	}

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

{#snippet editItemCard(item: InventoryItem, location: string, index: number)}
	<div class="space-y-2 rounded-lg border bg-muted/30 p-2">
		<div class="flex items-center gap-2">
			<Input bind:value={item.name} class="h-7 flex-1 text-xs" placeholder="Item Name" />
			<Input type="number" bind:value={item.quantity} class="h-7 w-16 text-xs" min="1" />
			<Button
				variant="ghost"
				size="icon"
				class="h-7 w-7 text-destructive"
				onclick={() => removeItem(location, index)}
			>
				<Trash2 class="h-3.5 w-3.5" />
			</Button>
		</div>
		<div class="flex items-center gap-2">
			<Input bind:value={item.category} class="h-7 w-24 text-xs" placeholder="Category" />
			<Input bind:value={item.description} class="h-7 flex-1 text-xs" placeholder="Description" />
		</div>
		<div class="flex items-center gap-2">
			<label class="flex cursor-pointer items-center gap-1 text-xs text-muted-foreground">
				<input type="checkbox" bind:checked={item.equipped} class="rounded border-border" />
				Equipped
			</label>
		</div>
	</div>
{/snippet}

{#snippet headerAction()}
	{#if onUpdate}
		{#if isEditing}
			<div class="flex gap-1">
				<Button variant="ghost" size="icon" class="h-6 w-6" onclick={save} title="Save">
					<Save class="h-3.5 w-3.5 text-primary" />
				</Button>
				<Button variant="ghost" size="icon" class="h-6 w-6" onclick={cancel} title="Cancel">
					<X class="h-3.5 w-3.5 text-muted-foreground" />
				</Button>
			</div>
		{:else}
			<Button
				variant="ghost"
				size="icon"
				class="h-6 w-6"
				onclick={startEditing}
				title="Edit Inventory"
			>
				<Edit2 class="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />
			</Button>
		{/if}
	{/if}
{/snippet}

<WidgetBase title="Inventory" icon={iconSnippet} action={headerAction}>
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
			On Person ({isEditing ? editInventory.length : totalOnPerson})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'stored'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'stored')}
		>
			<Home class="h-3 w-3" />
			Stored ({isEditing
				? Object.values(editStored).reduce((s, i) => s + i.length, 0)
				: totalStored})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'assets'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'assets')}
		>
			<Landmark class="h-3 w-3" />
			Assets ({isEditing ? editAssets.length : totalAssets})
		</button>
	</div>

	<!-- Content area -->
	<div class="max-h-64 space-y-1.5 overflow-y-auto">
		{#if isEditing}
			<!-- EDIT MODE -->
			{#if activeTab === 'onPerson'}
				<div class="space-y-2">
					{#each editInventory as item, i}
						{@render editItemCard(item, 'onPerson', i)}
					{/each}
					<Button
						variant="outline"
						size="sm"
						class="h-7 w-full text-xs"
						onclick={() => addItem('onPerson')}
					>
						<Plus class="mr-1 h-3 w-3" /> Add Item
					</Button>
				</div>
			{:else if activeTab === 'stored'}
				<div class="space-y-4">
					{#each Object.entries(editStored) as [location, items]}
						<div class="space-y-2 rounded-lg border border-border p-2">
							<div class="flex items-center justify-between">
								<Input
									value={location}
									oninput={(e) => {
										const newLoc = e.currentTarget.value;
										if (newLoc && newLoc !== location) {
											const val = editStored[location];
											delete editStored[location];
											editStored[newLoc] = val;
										}
									}}
									class="h-6 w-1/2 text-xs font-medium"
								/>
								<Button
									variant="ghost"
									size="icon"
									class="h-6 w-6 text-destructive"
									onclick={() => removeStorageLocation(location)}
								>
									<Trash2 class="h-3 w-3" />
								</Button>
							</div>
							<div class="space-y-2 border-l-2 border-muted pl-2">
								{#each items as item, i}
									{@render editItemCard(item, location, i)}
								{/each}
								<Button
									variant="ghost"
									size="sm"
									class="h-6 w-full justify-start text-xs"
									onclick={() => addItem(location)}
								>
									<Plus class="mr-1 h-3 w-3" /> Add Item to {location}
								</Button>
							</div>
						</div>
					{/each}
					<Button
						variant="outline"
						size="sm"
						class="h-7 w-full text-xs"
						onclick={addStorageLocation}
					>
						<Plus class="mr-1 h-3 w-3" /> Add Storage Location
					</Button>
				</div>
			{:else if activeTab === 'assets'}
				<div class="space-y-2">
					{#each editAssets as asset, i}
						<div class="flex items-center gap-2">
							<Input bind:value={editAssets[i]} class="h-7 flex-1 text-xs" />
							<Button
								variant="ghost"
								size="icon"
								class="h-7 w-7 text-destructive"
								onclick={() => removeAsset(i)}
							>
								<Trash2 class="h-3.5 w-3.5" />
							</Button>
						</div>
					{/each}
					<Button variant="outline" size="sm" class="h-7 w-full text-xs" onclick={addAsset}>
						<Plus class="mr-1 h-3 w-3" /> Add Asset
					</Button>
				</div>
			{/if}
		{:else}
			<!-- VIEW MODE -->
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
							<div class="flex h-8 w-8 items-center justify-center rounded bg-muted text-sm">
								🏠
							</div>
							<span class="text-sm font-medium">{asset}</span>
						</div>
					{/each}
				{/if}
			{/if}
		{/if}
	</div>
</WidgetBase>
