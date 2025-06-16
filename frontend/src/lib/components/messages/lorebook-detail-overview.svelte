<script lang="ts">
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import { LorebookDetailView, ExportDialog } from '$lib/components/lorebooks';
	import { toast } from 'svelte-sonner';
	import type {
		Lorebook,
		LorebookEntry,
		UpdateLorebookPayload,
		CreateLorebookEntryPayload,
		UpdateLorebookEntryPayload
	} from '$lib/types';

	let {
		lorebookId
	}: {
		lorebookId: string;
	} = $props();

	let lorebook = $state<Lorebook | null>(null);
	let isLoading = $state(true);
	let error = $state<string | null>(null);
	let showExportDialog = $state(false);

	// Track previous lorebook ID for transition detection
	let previousLorebookId = $state<string | null>(null);
	let isTransitioning = $state(false);

	// Load lorebook and entries on mount or when lorebookId changes
	$effect(() => {
		if (lorebookId && lorebookId !== previousLorebookId) {
			if (previousLorebookId !== null) {
				// This is a lorebook change, trigger transition
				isTransitioning = true;
				setTimeout(() => {
					loadLorebookData();
					setTimeout(() => {
						isTransitioning = false;
					}, 100);
				}, 200);
			} else {
				// Initial load
				loadLorebookData();
			}
			previousLorebookId = lorebookId;
		}
	});

	async function loadLorebookData() {
		isLoading = true;
		error = null;

		try {
			// Only load lorebooks if not already loaded
			if (lorebookStore.lorebooks.length === 0 && !lorebookStore.isLoading) {
				await lorebookStore.loadLorebooks();
			}

			// Find the current lorebook
			const currentLorebook = lorebookStore.lorebooks.find((l) => l.id === lorebookId);
			if (!currentLorebook) {
				error = 'Lorebook not found';
				return;
			}

			lorebook = currentLorebook;

			// Select the lorebook to load its entries
			await lorebookStore.selectLorebook(currentLorebook);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load lorebook';
		} finally {
			isLoading = false;
		}
	}

	function handleBack() {
		// Dispatch event to go back to lorebook list
		const event = new CustomEvent('backToLorebookList');
		document.dispatchEvent(event);
	}

	async function handleUpdateLorebook(id: string, data: UpdateLorebookPayload): Promise<boolean> {
		const success = await lorebookStore.updateLorebook(id, data);
		if (success) {
			toast.success('Lorebook updated successfully!');
			// Update local lorebook reference
			if (lorebook) {
				lorebook = { ...lorebook, ...data, updated_at: new Date().toISOString() };
			}
		} else if (lorebookStore.error) {
			toast.error(`Failed to update lorebook: ${lorebookStore.error}`);
		}
		return success;
	}

	async function handleDeleteLorebook(id: string): Promise<boolean> {
		const success = await lorebookStore.deleteLorebook(id);
		if (success) {
			toast.success('Lorebook deleted successfully!');
			handleBack(); // Navigate back to list after deletion
		} else if (lorebookStore.error) {
			toast.error(`Failed to delete lorebook: ${lorebookStore.error}`);
		}
		return success;
	}

	function handleExportLorebook(lorebook: Lorebook) {
		showExportDialog = true;
	}

	async function handleExportFormat(format: 'scribe_minimal' | 'silly_tavern_full') {
		if (!lorebook) return;

		const exported = await lorebookStore.exportLorebook(lorebook.id, format);
		if (exported) {
			const blob = new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			const formatSuffix = format === 'scribe_minimal' ? '_scribe' : '_sillytavern';
			a.download = `${lorebook.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}${formatSuffix}_lorebook.json`;
			a.click();
			URL.revokeObjectURL(url);
			toast.success('Lorebook exported successfully!');
		} else if (lorebookStore.error) {
			toast.error(`Failed to export lorebook: ${lorebookStore.error}`);
		}

		showExportDialog = false;
	}

	async function handleCreateEntry(
		lorebookId: string,
		data: CreateLorebookEntryPayload
	): Promise<LorebookEntry | null> {
		const entry = await lorebookStore.createEntry(lorebookId, data);
		if (entry) {
			toast.success('Entry created successfully!');
		} else if (lorebookStore.error) {
			toast.error(`Failed to create entry: ${lorebookStore.error}`);
		}
		return entry;
	}

	async function handleUpdateEntry(
		lorebookId: string,
		entryId: string,
		data: UpdateLorebookEntryPayload
	): Promise<boolean> {
		const success = await lorebookStore.updateEntry(lorebookId, entryId, data);
		if (success) {
			toast.success('Entry updated successfully!');
		} else if (lorebookStore.error) {
			toast.error(`Failed to update entry: ${lorebookStore.error}`);
		}
		return success;
	}

	async function handleDeleteEntry(lorebookId: string, entryId: string): Promise<boolean> {
		const success = await lorebookStore.deleteEntry(lorebookId, entryId);
		if (success) {
			toast.success('Entry deleted successfully!');
		} else if (lorebookStore.error) {
			toast.error(`Failed to delete entry: ${lorebookStore.error}`);
		}
		return success;
	}

	function handleToggleEntry(entry: LorebookEntry) {
		handleUpdateEntry(entry.lorebook_id, entry.id, { is_enabled: !entry.is_enabled });
	}
</script>

<div class="w-full px-4">
<div
	class="relative mx-auto max-w-6xl"
	style="opacity: {isTransitioning ? 0.3 : 1}; transition: opacity 300ms ease-in-out;"
>
	<!-- Show error state or not found state immediately -->
	{#if error}
		<div class="py-12 text-center">
			<h2 class="mb-4 text-2xl font-bold text-destructive">Error</h2>
			<p class="mb-4 text-muted-foreground">{error}</p>
			<button onclick={handleBack} class="text-primary hover:underline">
				← Back to Lorebooks
			</button>
		</div>
	{:else if !isLoading && !lorebook}
		<div class="py-12 text-center">
			<h2 class="mb-4 text-2xl font-bold text-muted-foreground">Lorebook Not Found</h2>
			<button onclick={handleBack} class="text-primary hover:underline">
				← Back to Lorebooks
			</button>
		</div>
	{:else}
		<!-- Show lorebook content (or skeleton while loading) -->
		{#if lorebook}
			<LorebookDetailView
				{lorebook}
				entries={lorebookStore.entries}
				isLoading={lorebookStore.isLoadingEntries}
				onBack={handleBack}
				onUpdateLorebook={handleUpdateLorebook}
				onDeleteLorebook={handleDeleteLorebook}
				onExportLorebook={handleExportLorebook}
				onCreateEntry={handleCreateEntry}
				onUpdateEntry={handleUpdateEntry}
				onDeleteEntry={handleDeleteEntry}
				onToggleEntry={handleToggleEntry}
			/>
		{:else}
			<!-- Loading skeleton that matches the layout -->
			<div class="space-y-6">
				<!-- Header skeleton -->
				<div class="flex items-center justify-between">
					<div class="space-y-2">
						<div class="h-8 w-64 animate-pulse rounded bg-muted"></div>
						<div class="h-4 w-96 animate-pulse rounded bg-muted"></div>
					</div>
					<div class="flex gap-2">
						<div class="h-9 w-20 animate-pulse rounded bg-muted"></div>
						<div class="h-9 w-20 animate-pulse rounded bg-muted"></div>
						<div class="h-9 w-20 animate-pulse rounded bg-muted"></div>
					</div>
				</div>

				<!-- Content skeleton -->
				<div class="space-y-4">
					{#each Array(3) as _}
						<div class="space-y-3 rounded-lg border p-4">
							<div class="h-5 w-48 animate-pulse rounded bg-muted"></div>
							<div class="h-4 w-full animate-pulse rounded bg-muted"></div>
							<div class="h-4 w-3/4 animate-pulse rounded bg-muted"></div>
						</div>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Loading overlay -->
		{#if isLoading}
			<div
				class="absolute inset-0 flex items-center justify-center bg-background/80 backdrop-blur-sm"
			>
				<div
					class="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"
				></div>
			</div>
		{/if}
	{/if}

	<!-- Export Format Dialog -->
	<ExportDialog
		bind:open={showExportDialog}
		onClose={() => (showExportDialog = false)}
		onExport={handleExportFormat}
	/>
</div>
</div>
