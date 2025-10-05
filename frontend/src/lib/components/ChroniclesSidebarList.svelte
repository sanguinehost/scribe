<script lang="ts">
	import { onMount, createEventDispatcher } from 'svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { Button as ButtonComponent } from './ui/button';
	import { ScrollText, Plus } from 'lucide-svelte';
	import { slideAndFade } from '$lib/utils/transitions';

	const dispatch = createEventDispatcher<{
		selectChronicle: { chronicleId: string };
		viewAllChronicles: void;
		createChronicle: void;
	}>();

	// Load chronicles on mount
	onMount(async () => {
		// Always load if we don't have any chronicles yet
		if (chronicleStore.chronicles.length === 0 && !chronicleStore.isLoading) {
			await chronicleStore.loadChronicles();
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
			{#each Array(3) as _}
				<div class="animate-pulse">
					<div class="h-10 rounded border border-primary/10 bg-primary/5"></div>
				</div>
			{/each}
		</div>
	{:else if chronicleStore.chronicles.length === 0}
		<!-- Empty state -->
		<div class="flex flex-1 items-center justify-center p-4">
			<div class="text-center">
				<ScrollText class="mx-auto mb-2 h-8 w-8 text-primary/50" />
				<p class="mb-2 text-sm text-muted-foreground">No chronicles yet</p>
				<ButtonComponent
					variant="outline"
					size="sm"
					onclick={handleCreateChronicle}
					class="border-primary/20 hover:border-primary/30 hover:bg-primary/10"
				>
					<Plus class="mr-1 h-4 w-4" />
					Create First
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
