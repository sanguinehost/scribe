<script lang="ts">
	import { onMount, createEventDispatcher } from 'svelte';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import { Button } from './ui/button';
	import { BookOpen, Plus } from 'lucide-svelte';

	const dispatch = createEventDispatcher<{
		selectLorebook: { lorebookId: string };
		viewAllLorebooks: void;
	}>();

	onMount(() => {
		lorebookStore.loadLorebooks();
	});

	function handleSelectLorebook(lorebookId: string) {
		dispatch('selectLorebook', { lorebookId });
	}

	function handleViewAll() {
		dispatch('viewAllLorebooks');
	}
</script>

<div class="flex flex-col h-full">
	<!-- Header -->
	<div class="p-4 border-b">
		<div class="flex items-center justify-between">
			<h3 class="font-medium text-sm">Lorebooks</h3>
			<Button variant="ghost" size="sm" onclick={handleViewAll}>
				View All
			</Button>
		</div>
	</div>

	<!-- Loading state -->
	{#if lorebookStore.isLoading}
		<div class="p-4 space-y-2">
			{#each Array(3) as _}
				<div class="animate-pulse">
					<div class="h-10 bg-muted rounded"></div>
				</div>
			{/each}
		</div>
	{:else if lorebookStore.lorebooks.length === 0}
		<!-- Empty state -->
		<div class="flex-1 flex items-center justify-center p-4">
			<div class="text-center">
				<BookOpen class="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
				<p class="text-sm text-muted-foreground mb-2">No lorebooks yet</p>
				<Button variant="outline" size="sm" onclick={handleViewAll}>
					<Plus class="h-4 w-4 mr-1" />
					Create First
				</Button>
			</div>
		</div>
	{:else}
		<!-- Lorebook list -->
		<div class="flex-1 overflow-auto">
			<div class="p-2 space-y-1">
				{#each lorebookStore.lorebooks.slice(0, 10) as lorebook (lorebook.id)}
					<button
						class="w-full text-left p-2 rounded-md hover:bg-muted transition-colors group"
						onclick={() => handleSelectLorebook(lorebook.id)}
					>
						<div class="flex items-center gap-2">
							<BookOpen class="h-4 w-4 text-muted-foreground group-hover:text-foreground" />
							<div class="flex-1 min-w-0">
								<div class="text-sm font-medium truncate">{lorebook.name}</div>
								{#if lorebook.description}
									<div class="text-xs text-muted-foreground truncate">{lorebook.description}</div>
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