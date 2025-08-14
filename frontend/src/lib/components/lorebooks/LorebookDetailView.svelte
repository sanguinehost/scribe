<script lang="ts">
	import type {
		Lorebook,
		LorebookEntry,
		UpdateLorebookPayload,
		CreateLorebookEntryPayload,
		UpdateLorebookEntryPayload
	} from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Dialog, DialogContent, DialogHeader, DialogTitle } from '$lib/components/ui/dialog';
	import { ArrowLeft, Edit, Download, Trash } from 'lucide-svelte';
	import LorebookForm from './LorebookForm.svelte';
	import LorebookEntryList from './LorebookEntryList.svelte';
	import LorebookEntryForm from './LorebookEntryForm.svelte';

	interface Props {
		lorebook: Lorebook;
		entries: LorebookEntry[];
		isLoading?: boolean;
		onBack?: () => void;
		onUpdateLorebook?: (id: string, data: UpdateLorebookPayload) => Promise<boolean>;
		onDeleteLorebook?: (id: string) => Promise<boolean>;
		onExportLorebook?: (lorebook: Lorebook) => void;
		onCreateEntry?: (
			lorebookId: string,
			data: CreateLorebookEntryPayload
		) => Promise<LorebookEntry | null>;
		onUpdateEntry?: (
			lorebookId: string,
			entryId: string,
			data: UpdateLorebookEntryPayload
		) => Promise<boolean>;
		onDeleteEntry?: (lorebookId: string, entryId: string) => Promise<boolean>;
		onToggleEntry?: (entry: LorebookEntry) => void;
	}

	let {
		lorebook,
		entries,
		isLoading = false,
		onBack,
		onUpdateLorebook,
		onDeleteLorebook,
		onExportLorebook,
		onCreateEntry,
		onUpdateEntry,
		onDeleteEntry,
		onToggleEntry
	}: Props = $props();

	let showEditLorebook = $state(false);
	let showCreateEntry = $state(false);
	let showEditEntry = $state(false);
	let editingEntry = $state<LorebookEntry | null>(null);
	let showDeleteLorebook = $state(false);

	async function handleUpdateLorebook(data: UpdateLorebookPayload) {
		if (onUpdateLorebook) {
			const success = await onUpdateLorebook(lorebook.id, data);
			if (success) {
				showEditLorebook = false;
			}
		}
	}

	async function handleDeleteLorebook() {
		console.log('Delete lorebook clicked for:', lorebook.id);
		if (onDeleteLorebook) {
			console.log('Calling onDeleteLorebook...');
			const success = await onDeleteLorebook(lorebook.id);
			console.log('Delete result:', success);
			if (success) {
				showDeleteLorebook = false; // Close dialog only on success
				onBack?.();
			} else {
				// Keep dialog open on failure so user can see the error and try again
				console.log('Delete failed, keeping dialog open');
			}
		} else {
			console.log('onDeleteLorebook not provided');
		}
	}

	function handleExportLorebook() {
		onExportLorebook?.(lorebook);
	}

	function handleCancelDelete() {
		showDeleteLorebook = false;
	}

	async function handleCreateEntry(data: CreateLorebookEntryPayload | UpdateLorebookEntryPayload) {
		if (onCreateEntry && 'entry_title' in data) {
			// This is a CreateLorebookEntryPayload (has required entry_title)
			const entry = await onCreateEntry(lorebook.id, data as CreateLorebookEntryPayload);
			if (entry) {
				showCreateEntry = false;
			}
		}
	}

	function handleEditEntry(entry: LorebookEntry) {
		editingEntry = entry;
		showEditEntry = true;
	}

	async function handleUpdateEntry(data: UpdateLorebookEntryPayload) {
		if (onUpdateEntry && editingEntry) {
			const success = await onUpdateEntry(lorebook.id, editingEntry.id, data);
			if (success) {
				showEditEntry = false;
				editingEntry = null;
			}
		}
	}

	async function handleDeleteEntry(entry: LorebookEntry) {
		if (onDeleteEntry) {
			await onDeleteEntry(lorebook.id, entry.id);
		}
	}

	function handleToggleEntry(entry: LorebookEntry) {
		if (onUpdateEntry) {
			onUpdateEntry(lorebook.id, entry.id, { is_enabled: !entry.is_enabled });
		}
	}
</script>

<div class="space-y-6">
	<!-- Header -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-4">
			{#if onBack}
				<Button variant="ghost" size="sm" onclick={onBack}>
					<ArrowLeft class="mr-2 h-4 w-4" />
					Back to Lorebooks
				</Button>
			{/if}
			<div>
				<h1 class="text-3xl font-bold">{lorebook.name}</h1>
				{#if lorebook.description}
					<p class="mt-1 text-muted-foreground">{lorebook.description}</p>
				{/if}
			</div>
		</div>

		<div class="flex gap-2">
			<!-- Edit Lorebook -->
			<Button variant="outline" onclick={() => (showEditLorebook = true)}>
				<Edit class="mr-2 h-4 w-4" />
				Edit
			</Button>

			<!-- Export Lorebook -->
			<Button variant="outline" onclick={handleExportLorebook}>
				<Download class="mr-2 h-4 w-4" />
				Export
			</Button>

			<!-- Delete Lorebook -->
			<Button variant="destructive" onclick={() => (showDeleteLorebook = true)}>
				<Trash class="mr-2 h-4 w-4" />
				Delete
			</Button>
		</div>
	</div>

	<!-- Lorebook Info -->
	<div class="grid grid-cols-2 gap-4 rounded-lg bg-muted p-4 md:grid-cols-4">
		<div>
			<div class="text-sm font-medium">Source Format</div>
			<div class="text-sm text-muted-foreground">{lorebook.source_format}</div>
		</div>
		<div>
			<div class="text-sm font-medium">Visibility</div>
			<div class="text-sm text-muted-foreground">{lorebook.is_public ? 'Public' : 'Private'}</div>
		</div>
		<div>
			<div class="text-sm font-medium">Entries</div>
			<div class="text-sm text-muted-foreground">{entries.length}</div>
		</div>
		<div>
			<div class="text-sm font-medium">Last Updated</div>
			<div class="text-sm text-muted-foreground">
				{new Date(lorebook.updated_at).toLocaleDateString()}
			</div>
		</div>
	</div>

	<!-- Entries Section -->
	<LorebookEntryList
		{entries}
		{isLoading}
		onCreateNew={() => (showCreateEntry = true)}
		onEditEntry={handleEditEntry}
		onDeleteEntry={handleDeleteEntry}
		onToggleEntry={handleToggleEntry}
	/>

	<!-- Create Entry Dialog -->
	<Dialog bind:open={showCreateEntry}>
		<DialogContent class="max-w-4xl">
			<DialogHeader>
				<DialogTitle>Create New Entry</DialogTitle>
			</DialogHeader>
			<LorebookEntryForm
				{isLoading}
				onSubmit={handleCreateEntry}
				onCancel={() => (showCreateEntry = false)}
			/>
		</DialogContent>
	</Dialog>

	<!-- Edit Entry Dialog -->
	<Dialog bind:open={showEditEntry}>
		<DialogContent class="max-w-4xl">
			<DialogHeader>
				<DialogTitle>Edit Entry</DialogTitle>
			</DialogHeader>
			<LorebookEntryForm
				entry={editingEntry}
				{isLoading}
				onSubmit={handleUpdateEntry}
				onCancel={() => {
					showEditEntry = false;
					editingEntry = null;
				}}
			/>
		</DialogContent>
	</Dialog>

	<!-- Edit Lorebook Dialog -->
	<Dialog bind:open={showEditLorebook}>
		<DialogContent>
			<DialogHeader>
				<DialogTitle>Edit Lorebook</DialogTitle>
			</DialogHeader>
			<LorebookForm
				{lorebook}
				{isLoading}
				onSubmit={handleUpdateLorebook}
				onCancel={() => (showEditLorebook = false)}
			/>
		</DialogContent>
	</Dialog>

	<!-- Delete Lorebook Dialog -->
	<Dialog bind:open={showDeleteLorebook}>
		<DialogContent>
			<DialogHeader>
				<DialogTitle>Delete Lorebook</DialogTitle>
			</DialogHeader>
			<div class="py-4">
				<p class="text-sm text-muted-foreground">
					Are you sure you want to delete "{lorebook.name}"? This action cannot be undone and will
					delete all entries in this lorebook.
				</p>
			</div>
			<div class="flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2">
				<Button variant="outline" onclick={handleCancelDelete}>Cancel</Button>
				<Button variant="destructive" onclick={handleDeleteLorebook}>Delete Lorebook</Button>
			</div>
		</DialogContent>
	</Dialog>
</div>
