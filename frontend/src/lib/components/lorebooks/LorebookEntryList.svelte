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

	// Sort entries by creation date (most recent first)
	const sortedEntries = $derived(
		[...entries].sort((a, b) => {
			return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
		})
	);
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
		<!-- Empty state -->
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
				Add your first entry to start building this lorebook's knowledge base.
			</p>
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="mr-2 h-4 w-4" />
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
