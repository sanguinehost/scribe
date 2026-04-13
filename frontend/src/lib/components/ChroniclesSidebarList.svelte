<script lang="ts">
	import { onMount, createEventDispatcher, untrack } from 'svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { Button as ButtonComponent } from './ui/button';
	import { getIsAuthenticated, getIsAuthReady } from '$lib/auth.svelte';
	import { ScrollText, Plus } from 'lucide-svelte';
	import { slideAndFade } from '$lib/utils/transitions';

	const dispatch = createEventDispatcher<{
		selectChronicle: { chronicleId: string };
		viewAllChronicles: void;
		createChronicle: void;
	}>();

	// CRITICAL FIX: Use $effect for reactive data loading
	// This ensures chronicles load after auth becomes ready (including re-auth scenarios)
	// Pattern follows PersonaList.svelte and CharacterList.svelte
	let hasFetched = $state(false);

	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		// Initial fetch when auth becomes ready
		if (!hasFetched && authReady && authenticated) {
			console.log('[ChroniclesSidebarList] Auth ready detected, loading chronicles');
			// Use untrack to prevent infinite loops from state modifications inside loadChronicles
			untrack(() => {
				chronicleStore.loadChronicles();
				hasFetched = true;
			});
		}
	});

	// Listen for chronicle creation and deletion events
	onMount(() => {
		const handleChronicleCreated = async (_event: CustomEvent) => {
			console.log('[Chronicles Sidebar] New chronicle created, refreshing list');
			await chronicleStore.loadChronicles();
		};

		const handleChronicleDeleted = async (_event: CustomEvent) => {
			console.log('[Chronicles Sidebar] Chronicle deleted, refreshing list');
			await chronicleStore.loadChronicles();
		};

		window.addEventListener('chronicle-created', handleChronicleCreated as unknown as () => void);
		window.addEventListener('chronicle-deleted', handleChronicleDeleted as unknown as () => void);

		return () => {
			window.removeEventListener(
				'chronicle-created',
				handleChronicleCreated as unknown as () => void
			);
			window.removeEventListener(
				'chronicle-deleted',
				handleChronicleDeleted as unknown as () => void
			);
		};
	});

	// Expose a refresh function for the parent component
	export async function refresh() {
		await chronicleStore.loadChronicles();
	}

	function handleSelectChronicle(chronicleId: string) {
		dispatch('selectChronicle', { chronicleId });
	}

	function handleViewAll() {
		dispatch('viewAllChronicles');
	}

	function handleCreateChronicle() {
		dispatch('createChronicle');
	}
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="border-b p-4">
		<div class="flex items-center justify-between">
			<h3 class="text-sm font-medium">Chronicles</h3>
			<ButtonComponent variant="ghost" size="sm" onclick={handleViewAll}>View All</ButtonComponent>
		</div>
	</div>

	<!-- Loading state -->
	{#if chronicleStore.isLoading}
		<div class="space-y-2 p-4">
			{#each Array(3) as _, i (i)}
				<div class="animate-pulse">
					<div class="h-10 rounded border border-primary/10 bg-primary/5"></div>
				</div>
			{/each}
		</div>
	{:else if chronicleStore.chronicles.length === 0}
		<!-- Empty state -->
		<div class="flex flex-1 items-center justify-center p-4">
			<div class="flex flex-col items-center gap-4 text-center">
				<div class="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 text-primary">
					<ScrollText class="h-7 w-7" />
				</div>
				<div class="space-y-1">
					<p class="text-sm font-medium text-foreground">No chronicles yet</p>
					<p class="text-xs text-muted-foreground">Chronicles track your story's narrative arc and timeline.</p>
				</div>
				<ButtonComponent
					variant="outline"
					size="sm"
					onclick={handleCreateChronicle}
					class="rounded-full"
				>
					<Plus class="mr-1 h-3.5 w-3.5" />
					Create Chronicle
				</ButtonComponent>
			</div>
		</div>
	{:else}
		<!-- Chronicle list -->
		<div class="flex-1 overflow-auto">
			<div class="space-y-1 p-2">
				{#each chronicleStore.chronicles.slice(0, 10) as chronicle (chronicle.id)}
					{#key chronicle.id}
						<div
							in:slideAndFade={{ y: 20, duration: 300 }}
							out:slideAndFade={{ y: -20, duration: 200 }}
						>
							<button
								class="group w-full rounded-md border border-border/40 bg-muted/50 p-2 text-left transition-colors hover:border-primary hover:bg-muted/70"
								onclick={() => handleSelectChronicle(chronicle.id)}
							>
								<div class="flex items-center gap-2">
									<ScrollText class="h-4 w-4 text-primary/70" />
									<div class="min-w-0 flex-1">
										<div class="truncate text-sm font-medium">{chronicle.name}</div>
										<div class="flex items-center gap-4 text-xs text-muted-foreground">
											<span>{chronicle.event_count} events</span>
											<span>{chronicle.chat_session_count} chats</span>
										</div>
									</div>
								</div>
							</button>
						</div>
					{/key}
				{/each}

				{#if chronicleStore.chronicles.length > 10}
					<div class="p-2 text-center">
						<ButtonComponent variant="ghost" size="sm" onclick={handleViewAll}>
							+{chronicleStore.chronicles.length - 10} more
						</ButtonComponent>
					</div>
				{/if}
			</div>
		</div>

		<!-- Create button at bottom -->
		<div class="border-t p-4">
			<ButtonComponent variant="outline" size="sm" class="w-full" onclick={handleCreateChronicle}>
				<Plus class="mr-2 h-4 w-4" />
				New Chronicle
			</ButtonComponent>
		</div>
	{/if}
</div>
