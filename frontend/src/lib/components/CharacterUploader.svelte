<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import Loader from './icons/loader.svelte'; // Assuming a loader icon exists

	// Props to control the dialog visibility
	let {
		_open = $bindable(false),
		onOpenChange
	}: { _open: boolean; onOpenChange: (_value: boolean) => void } = $props();

	let selectedFile = $state<File | null>(null);
	let fileName = $state('');
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	// let fileInput: HTMLInputElement; // Remove binding variable

	const dispatch = createEventDispatcher();

	function handleFileChange(_event: Event) {
		const target = _event.target as HTMLInputElement;
		if (target.files && target.files.length > 0) {
			const file = target.files[0];
			if (file.type === 'image/png' || file.type === 'application/json') {
				selectedFile = file;
				fileName = file.name;
				error = null; // Clear previous errors
			} else {
				selectedFile = null;
				fileName = '';
				error = 'Invalid file type. Please select a PNG or JSON file.';
				target.value = ''; // Reset file input
			}
		} else {
			selectedFile = null;
			fileName = '';
		}
	}

	async function handleUpload() {
		if (!selectedFile) {
			error = 'Please select a file to upload.';
			return;
		}

		isLoading = true;
		error = null;

		try {
			const result = await _apiClient.uploadCharacter(selectedFile);

			if (result.isOk()) {
				console.log('Character upload successful:', result.value);
				console.log('✅ Avatar field:', result.value.avatar);
				console.log('✅ Full character object:', JSON.stringify(result.value, null, 2));
				dispatch('uploadSuccess', { character: result.value }); // Notify parent component with character data
				closeDialog(); // Close dialog on success
			} else {
				console.error('Character upload failed:', result.error);
				error = result.error.message;
			}
		} catch (e: unknown) {
			console.error('Upload failed:', e);
			error = e instanceof Error ? e.message : 'An unexpected error occurred during upload.';
		} finally {
			isLoading = false;
		}
	}

	function closeDialog() {
		// Reset state when closing
		selectedFile = null;
		fileName = '';
		isLoading = false;
		error = null;
		// Resetting via event target in handleFileChange is sufficient
		// if (fileInput) {
		// 	fileInput.value = ''; // Reset file input visually
		// }
		onOpenChange(false); // Call the prop function to update parent state
	}
</script>

<Dialog
	open={_open}
	onOpenChange={(value) => {
		if (!value) closeDialog();
		else onOpenChange(value);
	}}
>
	<DialogContent class="sm:max-w-[425px]">
		<DialogHeader>
			<DialogTitle>Upload Character Card</DialogTitle>
			<DialogDescription>Select a V2 character card PNG or JSON file to upload.</DialogDescription>
		</DialogHeader>
		<div class="grid gap-4 py-4">
			<div class="grid w-full max-w-sm items-center gap-1.5">
				<Label for="character-file">Character File</Label>
				<Input
					id="character-file"
					type="file"
					accept=".png,.json,image/png,application/json"
					onchange={handleFileChange}
					disabled={isLoading}
				/>
				{#if fileName}
					<p class="mt-1 text-sm text-muted-foreground">Selected: {fileName}</p>
				{/if}
			</div>
			{#if error}
				<p class="text-sm text-destructive">{error}</p>
			{/if}
		</div>
		<DialogFooter>
			<ButtonComponent variant="outline" onclick={closeDialog} disabled={isLoading}
				>Cancel</ButtonComponent
			>
			<ButtonComponent type="submit" onclick={handleUpload} disabled={isLoading || !selectedFile}>
				{#if isLoading}
					<Loader class="mr-2 h-4 w-4 animate-spin" />
				{/if}
				Upload
			</ButtonComponent>
		</DialogFooter>
	</DialogContent>
</Dialog>
