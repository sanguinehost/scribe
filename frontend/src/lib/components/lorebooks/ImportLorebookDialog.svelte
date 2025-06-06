<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription,
		DialogFooter
	} from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api';
	import type { LorebookUploadPayload, ScribeMinimalLorebook } from '$lib/types';
	import type { ApiError } from '$lib/errors/api';

	let { open = false }: { open: boolean } = $props();

	const dispatch = createEventDispatcher<{
		close: void;
		importSuccess: void;
	}>();

	let selectedFile: File | null = $state(null);
	let isImporting = $state(false);

	function handleFileChange(event: Event) {
		const target = event.target as HTMLInputElement;
		if (target.files && target.files.length > 0) {
			selectedFile = target.files[0];
		} else {
			selectedFile = null;
		}
	}

	function detectLorebookFormat(data: any): 'scribe_minimal' | 'silly_tavern_full' {
		if (data && data.entries) {
			// If entries is an array, it's likely Scribe format
			if (Array.isArray(data.entries)) {
				// Additional validation: check if entries have the expected Scribe structure
				if (data.entries.length > 0) {
					const firstEntry = data.entries[0];
					// Check for Scribe Minimal: entry has 'title', 'keywords' (array), and 'content'
					if (
						typeof firstEntry.title === 'string' &&
						Array.isArray(firstEntry.keywords) &&
						typeof firstEntry.content === 'string'
					) {
						return 'scribe_minimal';
					}
				}
				// If it's an array but doesn't match Scribe structure, still treat as Scribe
				// The backend will handle validation
				return 'scribe_minimal';
			}
			// If entries is an object (with string keys like "0", "1", etc.), it's SillyTavern format
			else if (typeof data.entries === 'object' && !Array.isArray(data.entries)) {
				return 'silly_tavern_full';
			}
		}
		// Default to SillyTavern if structure is unclear
		return 'silly_tavern_full';
	}

	async function handleImport() {
		if (!selectedFile) {
			toast.error('Please select a lorebook file to import.');
			return;
		}

		isImporting = true;
		try {
			const fileContent = await selectedFile.text();
			const payload = JSON.parse(fileContent);

			const detectedFormat = detectLorebookFormat(payload);
			let result;

			if (detectedFormat === 'scribe_minimal') {
				console.log('Importing as Scribe Minimal format');
				result = await apiClient.importLorebookScribeMinimal(payload as ScribeMinimalLorebook);
			} else {
				console.log('Importing as SillyTavern Full format');
				result = await apiClient.importLorebook(payload as LorebookUploadPayload);
			}

			if (result.isOk()) {
				toast.success('Lorebook imported successfully!');
				dispatch('importSuccess');
				dispatch('close');
			} else {
				toast.error(`Failed to import lorebook: ${(result as { error: ApiError }).error.message}`);
			}
		} catch (error: unknown) {
			console.error('Error importing lorebook:', error);
			const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
			toast.error(`An unexpected error occurred during import: ${errorMessage}`);
		} finally {
			isImporting = false;
			selectedFile = null; // Clear selected file after attempt
		}
	}

	function handleClose() {
		selectedFile = null;
		isImporting = false;
		dispatch('close');
	}
</script>

<Dialog bind:open onOpenChange={handleClose}>
	<DialogContent class="sm:max-w-[425px]">
		<DialogHeader>
			<DialogTitle>Import Lorebook</DialogTitle>
			<DialogDescription>
				Upload a lorebook file. The format (SillyTavern Full or Scribe Minimal) will be
				automatically detected.
			</DialogDescription>
		</DialogHeader>
		<div class="grid gap-4 py-4">
			<div class="grid gap-2">
				<Label for="lorebook-file">Lorebook File</Label>
				<Input id="lorebook-file" type="file" accept=".json" onchange={handleFileChange} />
			</div>
		</div>
		<DialogFooter>
			<Button variant="outline" onclick={handleClose} disabled={isImporting}>Cancel</Button>
			<Button onclick={handleImport} disabled={!selectedFile || isImporting}>
				{#if isImporting}
					Importing...
				{:else}
					Import
				{/if}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
