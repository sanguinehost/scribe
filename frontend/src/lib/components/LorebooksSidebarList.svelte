<script lang="ts">
	import { onMount, createEventDispatcher } from 'svelte';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import { Button } from './ui/button';
	import { BookOpen, Plus } from 'lucide-svelte';

	const dispatch = createEventDispatcher<{
		selectLorebook: { lorebookId: string };
		viewAllLorebooks: void;
	}>();

	// Only fetch on mount, not on every re-render
	let hasFetched = false;
	
	onMount(async () => {
		if (!hasFetched) {
			await lorebookStore.loadLorebooks();
			hasFetched = true;
		}
	});

	// Expose a refresh function for the parent component
	export async function refresh() {
		await lorebookStore.loadLorebooks();
	}

	function handleSelectLorebook(lorebookId: string) {
		dispatch('selectLorebook', { lorebookId });
	}

	function handleViewAll() {
		dispatch('viewAllLorebooks');
	}
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="border-b p-4">
		<div class="flex items-center justify-between">
			<h3 class="text-sm font-medium">Lorebooks</h3>
			<Button variant="ghost" size="sm" onclick={handleViewAll}>View All</Button>
		</div>
	</div>

	<!-- Loading state -->
	{#if lorebookStore.isLoading}
		<div class="space-y-2 p-4">
			{#each Array(3) as _}
				<div class="animate-pulse">
					<div class="h-10 rounded bg-muted"></div>
				</div>
			{/each}
		</div>
	{:else if lorebookStore.lorebooks.length === 0}
		<!-- Empty state -->
		<div class="flex flex-1 items-center justify-center p-4">
			<div class="text-center">
				<BookOpen class="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
				<p class="mb-2 text-sm text-muted-foreground">No lorebooks yet</p>
				<Button variant="outline" size="sm" onclick={handleViewAll}>
					<Plus class="mr-1 h-4 w-4" />
					Create First
				</Button>
			</div>
		</div>
	{:else}
		<!-- Lorebook list -->
		<div class="flex-1 overflow-auto">
			<div class="space-y-1 p-2">
				{#each lorebookStore.lorebooks.slice(0, 10) as lorebook (lorebook.id)}
					<button
						class="group w-full rounded-md p-2 text-left transition-colors hover:bg-muted"
						onclick={() => handleSelectLorebook(lorebook.id)}
					>
						<div class="flex items-center gap-2">
							<BookOpen class="h-4 w-4 text-muted-foreground group-hover:text-foreground" />
							<div class="min-w-0 flex-1">
								<div class="truncate text-sm font-medium">{lorebook.name}</div>
								{#if lorebook.description}
									<div class="truncate text-xs text-muted-foreground">{lorebook.description}</div>
								{/if}
							</div>
						</div>
					</button>
				{/each}

				{#if lorebookStore.lorebooks.length > 10}
					<div class="p-2 text-center">
						<Button variant="ghost" size="sm" onclick={handleViewAll}>
							+{lorebookStore.lorebooks.length - 10} more
						</Button>
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>
