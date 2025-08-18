<script lang="ts">
	import { onMount } from 'svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { apiClient } from '$lib/api';
	import type { PlayerChronicleWithCounts } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import {
		Card,
		CardContent,
		CardDescription,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import {
		AlertDialog,
		AlertDialogAction,
		AlertDialogCancel,
		AlertDialogContent,
		AlertDialogDescription,
		AlertDialogFooter,
		AlertDialogHeader,
		AlertDialogTitle
	} from '$lib/components/ui/alert-dialog';
	import { ScrollText, Plus, Calendar, MessageSquare, ArrowLeft, Trash2 } from 'lucide-svelte';
	import { toast } from 'svelte-sonner';
	import { slideAndFade } from '$lib/utils/transitions';

	const selectedChronicleStore = SelectedChronicleStore.fromContext();

	// Delete chronicle state
	let deleteChronicleDialogOpen = $state(false);
	let chronicleToDelete = $state<PlayerChronicleWithCounts | null>(null);
	let isDeletingChronicle = $state(false);

	// Only load chronicles if not already loaded
	onMount(() => {
		if (chronicleStore.chronicles.length === 0 && !chronicleStore.isLoading) {
			chronicleStore.loadChronicles();
		}
	});

	// Listen for chronicle creation and deletion events
	onMount(() => {
		const handleChronicleCreated = async (event: CustomEvent) => {
			console.log('[Chronicles List] New chronicle created, refreshing list');
			await chronicleStore.loadChronicles();
		};

		const handleChronicleDeleted = async (event: CustomEvent) => {
			console.log('[Chronicles List] Chronicle deleted, refreshing list');
			await chronicleStore.loadChronicles();
		};

		window.addEventListener(
			'chronicle-created',
			handleChronicleCreated as unknown as EventListener
		);
		window.addEventListener(
			'chronicle-deleted',
			handleChronicleDeleted as unknown as EventListener
		);

		return () => {
			window.removeEventListener(
				'chronicle-created',
				handleChronicleCreated as unknown as EventListener
			);
			window.removeEventListener(
				'chronicle-deleted',
				handleChronicleDeleted as unknown as EventListener
			);
		};
	});

	function handleSelectChronicle(chronicleId: string) {
		selectedChronicleStore.selectChronicle(chronicleId);
	}

	function handleCreateNew() {
		selectedChronicleStore.showCreating();
	}

	function formatDate(dateString: string): string {
		const date = new Date(dateString);
		return date.toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}

	function handleDeleteChronicleClick(event: Event, chronicle: PlayerChronicleWithCounts) {
		event.stopPropagation(); // Prevent card click
		chronicleToDelete = chronicle;
		deleteChronicleDialogOpen = true;
	}

	async function confirmDeleteChronicle() {
		if (!chronicleToDelete) return;

		isDeletingChronicle = true;
		try {
			const result = await apiClient.deleteChronicle(chronicleToDelete.id);
			if (result.isOk()) {
				toast.success('Chronicle deleted successfully');
				// Reload chronicles list
				await chronicleStore.loadChronicles();

				// Notify other components that a chronicle was deleted
				window.dispatchEvent(
					new CustomEvent('chronicle-deleted', {
						detail: { chronicleId: chronicleToDelete.id }
					})
				);
			} else {
				toast.error('Failed to delete chronicle', {
					description: result.error.message
				});
			}
		} finally {
			isDeletingChronicle = false;
			deleteChronicleDialogOpen = false;
			chronicleToDelete = null;
		}
	}
</script>

<div class="mx-auto max-w-4xl px-4">
	<div class="mb-8">
		<div class="flex items-center justify-between">
			<div>
				<h1 class="text-3xl font-bold">Chronicles</h1>
				<p class="mt-2 text-muted-foreground">Manage your story chronicles and their events</p>
			</div>
			<Button onclick={handleCreateNew} class="gap-2">
				<Plus class="h-4 w-4" />
				New Chronicle
			</Button>
		</div>
	</div>

	{#if chronicleStore.isLoading}
		<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each Array(6) as _}
				<Card>
					<CardHeader>
						<div class="animate-pulse">
							<div class="h-6 w-3/4 rounded bg-muted"></div>
							<div class="mt-2 h-4 w-full rounded bg-muted"></div>
						</div>
					</CardHeader>
					<CardContent>
						<div class="animate-pulse">
							<div class="h-4 w-1/2 rounded bg-muted"></div>
						</div>
					</CardContent>
				</Card>
			{/each}
		</div>
	{:else if chronicleStore.error}
		<Card>
			<CardContent class="py-12 text-center">
				<div class="text-destructive">
					<h3 class="mb-2 text-lg font-semibold">Failed to load chronicles</h3>
					<p class="text-sm">{chronicleStore.error}</p>
				</div>
				<Button variant="outline" onclick={() => chronicleStore.loadChronicles()} class="mt-4">
					Try Again
				</Button>
			</CardContent>
		</Card>
	{:else if chronicleStore.chronicles.length === 0}
		<Card>
			<CardContent class="py-12 text-center">
				<ScrollText class="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
				<h3 class="mb-2 text-lg font-semibold">No chronicles yet</h3>
				<p class="mb-6 text-sm text-muted-foreground">
					Create your first chronicle to start tracking story events
				</p>
				<Button onclick={handleCreateNew} class="gap-2">
					<Plus class="h-4 w-4" />
					Create First Chronicle
				</Button>
			</CardContent>
		</Card>
	{:else}
		<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each chronicleStore.chronicles as chronicle (chronicle.id)}
				{#key chronicle.id}
					<div
						in:slideAndFade={{ y: 20, duration: 300 }}
						out:slideAndFade={{ y: -20, duration: 200 }}
					>
						<Card class="relative overflow-hidden transition-colors hover:bg-muted/50">
							<button class="w-full text-left" onclick={() => handleSelectChronicle(chronicle.id)}>
								<CardHeader>
									<div class="flex items-start gap-3">
										<ScrollText class="mt-1 h-5 w-5 text-muted-foreground" />
										<div class="min-w-0 flex-1 pr-8">
											<CardTitle class="text-lg">{chronicle.name}</CardTitle>
											{#if chronicle.description}
												<CardDescription class="mt-1 line-clamp-2">
													{chronicle.description}
												</CardDescription>
											{/if}
										</div>
									</div>
								</CardHeader>
								<CardContent>
									<div class="flex items-center gap-4 text-sm text-muted-foreground">
										<div class="flex items-center gap-1">
											<MessageSquare class="h-4 w-4" />
											{chronicle.event_count} events
										</div>
										<div class="flex items-center gap-1">
											<ScrollText class="h-4 w-4" />
											{chronicle.chat_session_count} chats
										</div>
									</div>
									<div class="mt-3 flex items-center gap-1 text-xs text-muted-foreground">
										<Calendar class="h-3 w-3" />
										Created {formatDate(chronicle.created_at)}
									</div>
								</CardContent>
							</button>
							<!-- Delete button positioned absolutely in top-right -->
							<Button
								variant="ghost"
								size="icon"
								class="absolute right-2 top-2 h-8 w-8 opacity-60 hover:opacity-100"
								onclick={(e) => handleDeleteChronicleClick(e, chronicle)}
								title="Delete chronicle"
							>
								<Trash2 class="h-4 w-4 text-destructive" />
							</Button>
						</Card>
					</div>
				{/key}
			{/each}
		</div>
	{/if}
</div>

<!-- Delete Chronicle Confirmation Dialog -->
<AlertDialog bind:open={deleteChronicleDialogOpen}>
	<AlertDialogContent>
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Chronicle</AlertDialogTitle>
			<AlertDialogDescription>
				Are you sure you want to delete this chronicle? This action cannot be undone and will
				permanently delete all events associated with this chronicle.
				{#if chronicleToDelete}
					<div class="mt-4 rounded-md bg-muted p-3">
						<div class="font-medium">{chronicleToDelete.name}</div>
						{#if chronicleToDelete.description}
							<div class="text-sm text-muted-foreground">{chronicleToDelete.description}</div>
						{/if}
						<div class="mt-2 text-xs text-muted-foreground">
							{chronicleToDelete.event_count} events • {chronicleToDelete.chat_session_count} chat sessions
						</div>
					</div>
				{/if}
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel disabled={isDeletingChronicle}>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={confirmDeleteChronicle}
				disabled={isDeletingChronicle}
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
			>
				{isDeletingChronicle ? 'Deleting...' : 'Delete Chronicle'}
			</AlertDialogAction>
		</AlertDialogFooter>
	</AlertDialogContent>
</AlertDialog>
