<script lang="ts">
	import type { LorebookEntry } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Plus } from 'lucide-svelte';
	import LorebookEntryCard from './LorebookEntryCard.svelte';

	interface Props {
		entries: LorebookEntry[];
		isLoading?: boolean;
		onCreateNew?: () => void;
		onEditEntry?: (entry: LorebookEntry) => void;
		onDeleteEntry?: (entry: LorebookEntry) => void;
		onToggleEntry?: (entry: LorebookEntry) => void;
	}

	let { 
		entries, 
		isLoading = false, 
		onCreateNew, 
		onEditEntry, 
		onDeleteEntry, 
		onToggleEntry 
	}: Props = $props();

	// Sort entries by insertion order, then by creation date
	const sortedEntries = $derived(
		[...entries].sort((a, b) => {
			if (a.insertion_order !== b.insertion_order) {
				return a.insertion_order - b.insertion_order;
			}
			return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
		})
	);
</script>

<div class="space-y-4">
	<!-- Header with action buttons -->
	<div class="flex items-center justify-between">
		<h3 class="text-lg font-semibold">Entries ({entries.length})</h3>
		{#if onCreateNew}
			<Button onclick={onCreateNew}>
				<Plus class="h-4 w-4 mr-2" />
				Add Entry
			</Button>
		{/if}
	</div>

	<!-- Loading state -->
	{#if isLoading}
		<div class="space-y-4">
			{#each Array(3) as _}
				<div class="animate-pulse">
					<div class="bg-muted rounded-lg p-6 space-y-3">
						<div class="flex justify-between">
							<div class="h-4 bg-muted-foreground/20 rounded w-1/4"></div>
							<div class="flex gap-2">
								<div class="h-6 w-6 bg-muted-foreground/20 rounded"></div>
								<div class="h-6 w-6 bg-muted-foreground/20 rounded"></div>
								<div class="h-6 w-6 bg-muted-foreground/20 rounded"></div>
							</div>
						</div>
						<div class="h-3 bg-muted-foreground/20 rounded w-3/4"></div>
						<div class="space-y-2">
							<div class="h-2 bg-muted-foreground/20 rounded"></div>
							<div class="h-2 bg-muted-foreground/20 rounded w-5/6"></div>
							<div class="h-2 bg-muted-foreground/20 rounded w-1/2"></div>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{:else if entries.length === 0}
		<!-- Empty state -->
		<div class="text-center py-12">
			<div class="mx-auto h-16 w-16 text-muted-foreground mb-4">
				<svg class="h-full w-full" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
				</svg>
			</div>
			<h4 class="text-lg font-medium text-muted-foreground mb-2">No entries yet</h4>
			<p class="text-sm text-muted-foreground mb-4">
				Add your first entry to start building this lorebook's knowledge base.
			</p>
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="h-4 w-4 mr-2" />
					Add Your First Entry
				</Button>
			{/if}
		</div>
	{:else}
		<!-- Entry list -->
		<div class="space-y-4">
			{#each sortedEntries as entry (entry.id)}
				<LorebookEntryCard 
					{entry} 
					onEdit={onEditEntry}
					onDelete={onDeleteEntry}
					onToggleEnabled={onToggleEntry}
				/>
			{/each}
		</div>
	{/if}
</div>