<script lang="ts">
	import { onMount } from 'svelte';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import { LorebookList, LorebookForm, ExportDialog, ImportLorebookDialog } from '$lib/components/lorebooks';
	import { Dialog, DialogContent, DialogHeader, DialogTitle } from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { toast } from 'svelte-sonner';
	import type { Lorebook, CreateLorebookPayload, UpdateLorebookPayload } from '$lib/types';

	let showCreateDialog = $state(false);
	let showDeleteDialog = $state(false);
	let showExportDialog = $state(false);
	let showImportDialog = $state(false);
	let exportingLorebook = $state<Lorebook | null>(null);
	let deletingLorebook = $state<Lorebook | null>(null);

	// Only load lorebooks if not already loaded
	onMount(() => {
		if (lorebookStore.lorebooks.length === 0 && !lorebookStore.isLoading) {
			lorebookStore.loadLorebooks();
		}
	});

	function handleCreateNew() {
		showCreateDialog = true;
	}

	function handleSelectLorebook(lorebook: Lorebook) {
		// Use an event dispatcher to notify parent components
		const event = new CustomEvent('selectLorebook', {
			detail: { lorebookId: lorebook.id }
		});
		document.dispatchEvent(event);
	}

	function handleEditLorebook(lorebook: Lorebook) {
		// Use an event dispatcher to notify parent components  
		const event = new CustomEvent('editLorebook', {
			detail: { lorebookId: lorebook.id }
		});
		document.dispatchEvent(event);
	}

	function handleDeleteLorebook(lorebook: Lorebook) {
		deletingLorebook = lorebook;
		showDeleteDialog = true;
	}

	function handleExportLorebook(lorebook: Lorebook) {
		exportingLorebook = lorebook;
		showExportDialog = true;
	}

	async function handleExportFormat(format: 'scribe_minimal' | 'silly_tavern_full') {
		if (!exportingLorebook) return;

		const exported = await lorebookStore.exportLorebook(exportingLorebook.id, format);
		if (exported) {
			const blob = new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			const formatSuffix = format === 'scribe_minimal' ? '_scribe' : '_sillytavern';
			a.download = `${exportingLorebook.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}${formatSuffix}_lorebook.json`;
			a.click();
			URL.revokeObjectURL(url);
			toast.success('Lorebook exported successfully!');
		} else if (lorebookStore.error) {
			toast.error(`Failed to export lorebook: ${lorebookStore.error}`);
		}

		showExportDialog = false;
		exportingLorebook = null;
	}

	async function handleCreateSubmit(data: CreateLorebookPayload | UpdateLorebookPayload) {
		const result = await lorebookStore.createLorebook(data as CreateLorebookPayload);
		if (result) {
			showCreateDialog = false;
			toast.success('Lorebook created successfully!');
			// Auto-select the newly created lorebook
			handleSelectLorebook(result);
		} else if (lorebookStore.error) {
			toast.error(`Failed to create lorebook: ${lorebookStore.error}`);
		}
	}

	async function confirmDelete() {
		if (deletingLorebook) {
			const success = await lorebookStore.deleteLorebook(deletingLorebook.id);
			if (success) {
				toast.success('Lorebook deleted successfully!');
			} else if (lorebookStore.error) {
				toast.error(`Failed to delete lorebook: ${lorebookStore.error}`);
			}
		}
		showDeleteDialog = false;
		deletingLorebook = null;
	}

	function cancelDelete() {
		showDeleteDialog = false;
		deletingLorebook = null;
	}
</script>

<div class="mx-auto max-w-6xl px-4 relative">
	<LorebookList
		lorebooks={lorebookStore.lorebooks}
		isLoading={lorebookStore.isLoading}
		onCreateNew={handleCreateNew}
		onUpload={() => (showImportDialog = true)}
		onSelectLorebook={handleSelectLorebook}
		onEditLorebook={handleEditLorebook}
		onDeleteLorebook={handleDeleteLorebook}
		onExportLorebook={handleExportLorebook}
	/>
	
	<!-- Loading overlay for initial load -->
	{#if lorebookStore.isLoading && lorebookStore.lorebooks.length === 0}
		<div class="absolute inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center">
			<div class="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
		</div>
	{/if}

	<!-- Create Lorebook Dialog -->
	<Dialog bind:open={showCreateDialog}>
		<DialogContent>
			<DialogHeader>
				<DialogTitle>Create New Lorebook</DialogTitle>
			</DialogHeader>
			<LorebookForm
				isLoading={lorebookStore.isLoading}
				onSubmit={handleCreateSubmit}
				onCancel={() => (showCreateDialog = false)}
			/>
		</DialogContent>
	</Dialog>

	<!-- Delete Confirmation Dialog -->
	<Dialog bind:open={showDeleteDialog}>
		<DialogContent>
			<DialogHeader>
				<DialogTitle>Delete Lorebook</DialogTitle>
			</DialogHeader>
			<div class="py-4">
				<p class="text-sm text-muted-foreground">
					Are you sure you want to delete this lorebook? This action cannot be undone and will
					delete all entries in this lorebook.
				</p>
				{#if deletingLorebook}
					<p class="mt-2 text-sm font-semibold">"{deletingLorebook.name}"</p>
				{/if}
			</div>

			<div class="flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2">
				<Button variant="outline" onclick={cancelDelete}>Cancel</Button>
				<Button variant="destructive" onclick={confirmDelete}>Delete Lorebook</Button>
			</div>
		</DialogContent>
	</Dialog>

	<!-- Export Format Dialog -->
	<ExportDialog
		bind:open={showExportDialog}
		onClose={() => {
			showExportDialog = false;
			exportingLorebook = null;
		}}
		onExport={handleExportFormat}
	/>
</div>

<ImportLorebookDialog
	open={showImportDialog}
	on:close={() => (showImportDialog = false)}
	on:importSuccess={() => lorebookStore.loadLorebooks()}
/>