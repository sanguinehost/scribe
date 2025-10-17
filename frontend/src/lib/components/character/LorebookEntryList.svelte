<script lang="ts">
	import type { LorebookEntry } from '$lib/types/character';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import {
		Plus,
		Search,
		X,
		ArrowUpDown,
		LayoutGrid,
		List,
		Eye,
		EyeOff,
		Edit,
		Trash,
		Zap
	} from '@lucide/svelte';
	import LorebookEntryCard from './LorebookEntryCard.svelte';

	interface Props {
		entries: LorebookEntry[];
		isLoading?: boolean;
		onCreateNew?: () => void;
		onEditEntry?: (entry: LorebookEntry, index: number) => void;
		onDeleteEntry?: (entry: LorebookEntry, index: number) => void;
		onToggleEntry?: (entry: LorebookEntry, index: number) => void;
	}

	let {
		entries,
		isLoading = false,
		onCreateNew,
		onEditEntry,
		onDeleteEntry,
		onToggleEntry
	}: Props = $props();

	// Search and sort state
	let searchQuery = $state('');
	let sortBy = $state<'insertion' | 'name' | 'priority' | 'enabled'>('insertion');
	let sortOrder = $state<'asc' | 'desc'>('asc');

	// View mode state with localStorage persistence
	type ViewMode = 'card' | 'list';
	let viewMode = $state<ViewMode>(
		(typeof localStorage !== 'undefined' &&
			(localStorage.getItem('lorebook-view-mode') as ViewMode)) ||
			'card'
	);

	// Persist view mode changes to localStorage
	$effect(() => {
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem('lorebook-view-mode', viewMode);
		}
	});

	// Sort options for dropdown
	const sortOptions = [
		{ value: 'insertion', label: 'Insertion Order' },
		{ value: 'name', label: 'Name' },
		{ value: 'priority', label: 'Priority' },
		{ value: 'enabled', label: 'Enabled Status' }
	];

	// Filter entries by search query
	const searchedEntries = $derived(
		entries.filter((entry) => {
			if (!searchQuery.trim()) return true;

			const query = searchQuery.toLowerCase();
			const matchesName = entry.name?.toLowerCase().includes(query);
			const matchesContent = entry.content?.toLowerCase().includes(query);
			const matchesKeys = entry.keys?.some((key) => key.toLowerCase().includes(query));

			return matchesName || matchesContent || matchesKeys;
		})
	);

	// Sort filtered entries
	const sortedEntries = $derived(
		[...searchedEntries].sort((a, b) => {
			let comparison = 0;

			switch (sortBy) {
				case 'name':
					comparison = (a.name || '').localeCompare(b.name || '');
					break;
				case 'priority':
					comparison = (a.priority || 0) - (b.priority || 0);
					break;
				case 'enabled':
					comparison = Number(b.enabled) - Number(a.enabled);
					break;
				default: // insertion
					comparison = a.insertion_order - b.insertion_order;
			}

			return sortOrder === 'asc' ? comparison : -comparison;
		})
	);

	function clearSearch() {
		searchQuery = '';
	}

	function toggleSortOrder() {
		sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
	}
</script>

<div class="space-y-4">
	<!-- Header with action buttons -->
	<div class="flex items-center justify-between">
		<h3 class="text-lg font-semibold">Entries ({entries.length})</h3>
		{#if onCreateNew}
			<Button onclick={onCreateNew}>
				<Plus class="mr-2 h-4 w-4" />
				Add Entry
			</Button>
		{/if}
	</div>

	<!-- Search and Sort Controls -->
	{#if entries.length > 0}
		<div class="flex flex-col gap-3">
			<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
				<!-- Search bar -->
				<div class="relative flex-1">
					<Search class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
					<Input
						type="text"
						placeholder="Search entries by name, keywords, or content..."
						bind:value={searchQuery}
						class="pl-9 pr-9"
					/>
					{#if searchQuery}
						<button
							onclick={clearSearch}
							class="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
							aria-label="Clear search"
						>
							<X class="h-4 w-4" />
						</button>
					{/if}
				</div>

				<!-- Sort controls -->
				<div class="flex items-center gap-2">
					<select
						bind:value={sortBy}
						class="flex h-9 items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
					>
						{#each sortOptions as option}
							<option value={option.value}>{option.label}</option>
						{/each}
					</select>
					<Button
						variant="outline"
						size="sm"
						onclick={toggleSortOrder}
						class="h-9 w-9 p-0"
						title={sortOrder === 'asc' ? 'Sort ascending' : 'Sort descending'}
					>
						<ArrowUpDown
							class="h-4 w-4 {sortOrder === 'desc' ? 'rotate-180' : ''} transition-transform"
						/>
					</Button>
				</div>
			</div>

			<!-- View mode toggle -->
			<div class="flex items-center gap-2">
				<span class="text-sm text-muted-foreground">View:</span>
				<div class="flex rounded-md border border-input">
					<Button
						variant={viewMode === 'card' ? 'secondary' : 'ghost'}
						size="sm"
						onclick={() => (viewMode = 'card')}
						class="rounded-r-none border-r px-3"
						title="Card view - Detailed view with full content"
					>
						<LayoutGrid class="h-4 w-4" />
					</Button>
					<Button
						variant={viewMode === 'list' ? 'secondary' : 'ghost'}
						size="sm"
						onclick={() => (viewMode = 'list')}
						class="rounded-l-none px-3"
						title="List view - Compact table view"
					>
						<List class="h-4 w-4" />
					</Button>
				</div>
			</div>
		</div>

		<!-- Results count -->
		{#if searchQuery}
			<p class="text-sm text-muted-foreground">
				Showing {sortedEntries.length} of {entries.length} entries
			</p>
		{/if}
	{/if}

	<!-- Loading state -->
	{#if isLoading}
		<div class="space-y-4">
			{#each Array(3) as _}
				<div class="animate-pulse">
					<div class="space-y-3 rounded-lg bg-muted p-6">
						<div class="flex justify-between">
							<div class="h-4 w-1/4 rounded bg-muted-foreground/20"></div>
							<div class="flex gap-2">
								<div class="h-6 w-6 rounded bg-muted-foreground/20"></div>
								<div class="h-6 w-6 rounded bg-muted-foreground/20"></div>
								<div class="h-6 w-6 rounded bg-muted-foreground/20"></div>
							</div>
						</div>
						<div class="h-3 w-3/4 rounded bg-muted-foreground/20"></div>
						<div class="space-y-2">
							<div class="h-2 rounded bg-muted-foreground/20"></div>
							<div class="h-2 w-5/6 rounded bg-muted-foreground/20"></div>
							<div class="h-2 w-1/2 rounded bg-muted-foreground/20"></div>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{:else if entries.length === 0}
		<!-- Empty state - no entries at all -->
		<div class="py-12 text-center">
			<div class="mx-auto mb-4 h-16 w-16 text-muted-foreground">
				<svg class="h-full w-full" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width={1}
						d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
					/>
				</svg>
			</div>
			<h4 class="mb-2 text-lg font-medium text-muted-foreground">No entries yet</h4>
			<p class="mb-4 text-sm text-muted-foreground">
				Add your first entry to start building this character's lorebook.
			</p>
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="mr-2 h-4 w-4" />
					Add Your First Entry
				</Button>
			{/if}
		</div>
	{:else if sortedEntries.length === 0}
		<!-- No search results -->
		<div class="py-12 text-center">
			<Search class="mx-auto mb-4 h-16 w-16 text-muted-foreground" />
			<h4 class="mb-2 text-lg font-medium text-muted-foreground">No entries found</h4>
			<p class="mb-4 text-sm text-muted-foreground">
				Try adjusting your search query or clear the search to see all entries.
			</p>
			<Button variant="outline" onclick={clearSearch}>
				<X class="mr-2 h-4 w-4" />
				Clear Search
			</Button>
		</div>
	{:else}
		<!-- Entry list with different view modes -->
		{#if viewMode === 'card'}
			<!-- Card view (default) -->
			<div class="space-y-4">
				{#each sortedEntries as entry, index (index)}
					<LorebookEntryCard
						{entry}
						{index}
						onEdit={onEditEntry}
						onDelete={onDeleteEntry}
						onToggleEnabled={onToggleEntry}
					/>
				{/each}
			</div>
		{:else}
			<!-- List view (table) -->
			<div class="rounded-lg border">
				<div class="overflow-x-auto">
					<table class="w-full">
						<thead class="border-b bg-muted/50">
							<tr>
								<th class="px-4 py-3 text-left text-sm font-medium">Name</th>
								<th class="px-4 py-3 text-left text-sm font-medium">Keywords</th>
								<th class="px-4 py-3 text-left text-sm font-medium">Status</th>
								<th class="px-4 py-3 text-left text-sm font-medium">Priority</th>
								<th class="px-4 py-3 text-right text-sm font-medium">Actions</th>
							</tr>
						</thead>
						<tbody>
							{#each sortedEntries as entry, index (index)}
								<tr
									class="border-b transition-colors last:border-0 hover:bg-muted/50 {!entry.enabled
										? 'opacity-60'
										: ''}"
								>
									<td class="px-4 py-3">
										<div class="flex items-center gap-2">
											<span class="font-medium">{entry.name || `Entry ${index + 1}`}</span>
											{#if entry.constant}
												<Badge variant="secondary" class="text-xs">
													<Zap class="mr-1 h-3 w-3" />
													Constant
												</Badge>
											{/if}
										</div>
									</td>
									<td class="px-4 py-3">
										<div class="flex flex-wrap gap-1">
											{#each (entry.keys || []).slice(0, 3) as keyword}
												<Badge variant="outline" class="text-xs">{keyword}</Badge>
											{/each}
											{#if (entry.keys?.length || 0) > 3}
												<Badge variant="outline" class="text-xs">
													+{(entry.keys?.length || 0) - 3}
												</Badge>
											{/if}
										</div>
									</td>
									<td class="px-4 py-3">
										<Badge variant={entry.enabled ? 'default' : 'secondary'} class="text-xs">
											{#if entry.enabled}
												<Eye class="mr-1 h-3 w-3" />
												Enabled
											{:else}
												<EyeOff class="mr-1 h-3 w-3" />
												Disabled
											{/if}
										</Badge>
									</td>
									<td class="px-4 py-3 text-sm">{entry.priority || '-'}</td>
									<td class="px-4 py-3">
										<div class="flex justify-end gap-1">
											{#if onToggleEntry}
												<Button
													variant="ghost"
													size="sm"
													onclick={() => onToggleEntry?.(entry, index)}
													class="h-8 w-8 p-0"
													aria-label={entry.enabled ? 'Disable entry' : 'Enable entry'}
												>
													{#if entry.enabled}
														<EyeOff class="h-4 w-4" />
													{:else}
														<Eye class="h-4 w-4" />
													{/if}
												</Button>
											{/if}
											{#if onEditEntry}
												<Button
													variant="ghost"
													size="sm"
													onclick={() => onEditEntry?.(entry, index)}
													class="h-8 w-8 p-0"
													aria-label="Edit entry"
												>
													<Edit class="h-4 w-4" />
												</Button>
											{/if}
											{#if onDeleteEntry}
												<Button
													variant="ghost"
													size="sm"
													onclick={() => onDeleteEntry?.(entry, index)}
													class="h-8 w-8 p-0 text-destructive hover:text-destructive"
													aria-label="Delete entry"
												>
													<Trash class="h-4 w-4" />
												</Button>
											{/if}
										</div>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
		{/if}
	{/if}
</div>
