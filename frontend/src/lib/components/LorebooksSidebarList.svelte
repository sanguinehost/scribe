<script lang="ts">
	import { createEventDispatcher, untrack } from 'svelte';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import { Button as ButtonComponent } from './ui/button';
	import { getIsAuthenticated, getIsAuthReady } from '$lib/auth.svelte';
	import { BookOpen, Plus } from 'lucide-svelte';
	import { slideAndFade } from '$lib/utils/transitions';

	const dispatch = createEventDispatcher<{
		selectLorebook: { lorebookId: string };
		viewAllLorebooks: void;
	}>();

	// CRITICAL FIX: Use $effect for reactive data loading
	// This ensures lorebooks load after auth becomes ready (including re-auth scenarios)
	// Pattern follows PersonaList.svelte and CharacterList.svelte
	let hasFetched = $state(false);

	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		// Initial fetch when auth becomes ready
		if (!hasFetched && authReady && authenticated) {
			console.log('[LorebooksSidebarList] Auth ready detected, loading lorebooks');
			// Use untrack to prevent infinite loops from state modifications inside loadLorebooks
			untrack(() => {
				lorebookStore.loadLorebooks();
				hasFetched = true;
			});
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
			<ButtonComponent variant="ghost" size="sm" onclick={handleViewAll}>View All</ButtonComponent>
		</div>
	</div>

	<!-- Loading state -->
	{#if lorebookStore.isLoading}
		<div class="space-y-2 p-4">
			{#each Array(3) as _, i (i)}
				<div class="animate-pulse">
					<div class="h-10 rounded border border-primary/10 bg-primary/5"></div>
				</div>
			{/each}
		</div>
	{:else if lorebookStore.lorebooks.length === 0}
		<!-- Empty state -->
		<div class="flex flex-1 items-center justify-center p-4">
			<div class="flex flex-col items-center gap-4 text-center">
				<div class="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
					<BookOpen class="h-7 w-7" />
				</div>
				<div class="space-y-1">
					<p class="text-sm font-medium text-foreground">No lorebooks yet</p>
					<p class="text-xs text-muted-foreground">Build your world's lore — places, factions, and history.</p>
				</div>
				<ButtonComponent
					variant="outline"
					size="sm"
					onclick={handleViewAll}
					class="rounded-full"
				>
					<Plus class="mr-1 h-3.5 w-3.5" />
					Create Lorebook
				</ButtonComponent>
			</div>
		</div>
	{:else}
		<!-- Lorebook list -->
		<div class="flex-1 overflow-auto">
			<div class="space-y-1 p-2">
				{#each lorebookStore.lorebooks.slice(0, 10) as lorebook (lorebook.id)}
					{#key lorebook.id}
						<div
							in:slideAndFade={{ y: 20, duration: 300 }}
							out:slideAndFade={{ y: -20, duration: 200 }}
						>
							<button
								class="group w-full rounded-md border border-border/40 bg-muted/50 p-2 text-left transition-colors hover:border-primary hover:bg-muted/70"
								onclick={() => handleSelectLorebook(lorebook.id)}
							>
								<div class="flex items-center gap-2">
									<BookOpen class="h-4 w-4 text-primary/70" />
									<div class="min-w-0 flex-1">
										<div class="truncate text-sm font-medium">{lorebook.name}</div>
										{#if lorebook.description}
											<div class="truncate text-xs text-muted-foreground">
												{lorebook.description}
											</div>
										{/if}
									</div>
								</div>
							</button>
						</div>
					{/key}
				{/each}

				{#if lorebookStore.lorebooks.length > 10}
					<div class="p-2 text-center">
						<ButtonComponent variant="ghost" size="sm" onclick={handleViewAll}>
							+{lorebookStore.lorebooks.length - 10} more
						</ButtonComponent>
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>
