<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { lorebookStore } from '$lib/stores/lorebook.svelte';
	import {
		LorebookList,
		LorebookForm,
		ExportDialog,
		ImportLorebookDialog
	} from '$lib/components/lorebooks';
	import { Dialog, DialogContent, DialogHeader, DialogTitle } from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { toast } from 'svelte-sonner';
	import type { Lorebook, CreateLorebookPayload, UpdateLorebookPayload } from '$lib/types';

	let showCreateDialog = $state(false);
	let showDeleteDialog = $state(false);
	let showExportDialog = $state(false);
	let showImportDialog = $state(false); // New state for import dialog
	let exportingLorebook = $state<Lorebook | null>(null);
	let deletingLorebook = $state<Lorebook | null>(null);

	// Load lorebooks on mount
	onMount(() => {
		lorebookStore.loadLorebooks();
	});

	function handleCreateNew() {
		showCreateDialog = true;
	}

	function handleSelectLorebook(lorebook: Lorebook) {
		goto(`/lorebooks/${lorebook.id}`);
	}

	function handleEditLorebook(lorebook: Lorebook) {
		goto(`/lorebooks/${lorebook.id}?edit=true`);
	}

	function handleDeleteLorebook(lorebook: Lorebook) {
		console.log('Delete clicked for lorebook:', lorebook);
		deletingLorebook = lorebook;
		console.log('Set deletingLorebook to:', deletingLorebook);
		showDeleteDialog = true;
		console.log('Set showDeleteDialog to true, deletingLorebook:', deletingLorebook);
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
		// Since this is for creation, we know it's CreateLorebookPayload
		const result = await lorebookStore.createLorebook(data as CreateLorebookPayload);
		if (result) {
			showCreateDialog = false;
			toast.success('Lorebook created successfully!');
			goto(`/lorebooks/${result.id}`);
		} else if (lorebookStore.error) {
			toast.error(`Failed to create lorebook: ${lorebookStore.error}`);
		}
	}

	async function confirmDelete() {
		console.log('Confirm delete clicked, deletingLorebook:', deletingLorebook);
		if (deletingLorebook) {
			console.log('Calling deleteLorebook for:', deletingLorebook.id);
			const success = await lorebookStore.deleteLorebook(deletingLorebook.id);
			console.log('Delete result:', success);
			if (success) {
				toast.success('Lorebook deleted successfully!');
			} else if (lorebookStore.error) {
				toast.error(`Failed to delete lorebook: ${lorebookStore.error}`);
			}
		} else {
			console.log('No lorebook to delete');
		}
		// Always close dialog and reset state
		showDeleteDialog = false;
		deletingLorebook = null;
	}

	function cancelDelete() {
		showDeleteDialog = false;
		deletingLorebook = null;
	}
</script>

<svelte:head>
	<title>Lorebooks - Sanguine Scribe</title>
</svelte:head>

<div class="container mx-auto py-6">
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
