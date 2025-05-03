<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { apiClient } from '$lib/services/apiClient';
	import * as Alert from '$lib/components/ui/alert';
	import { AlertCircle, CheckCircle2, Loader2, Upload } from 'lucide-svelte';

	// --- Props ---
	let { onUploadSuccess }: { onUploadSuccess: () => void } = $props();

	// --- State ---
	let selectedFile = $state<File | null>(null);
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let successMessage = $state<string | null>(null);
	let dragOver = $state(false); // For drag-and-drop visual feedback

	// --- Event Handlers ---
	const handleFileChange = (event: Event) => {
		const target = event.target as HTMLInputElement;
		if (target.files && target.files.length > 0) {
			if (target.files[0].type === 'image/png') {
				selectedFile = target.files[0];
				error = null; // Clear error if a valid file is selected
				successMessage = null; // Clear previous success
			} else {
				selectedFile = null;
				error = 'Invalid file type. Please select a PNG file.';
				successMessage = null;
			}
		} else {
			selectedFile = null;
		}
	};

	const handleUpload = async () => {
		if (!selectedFile) {
			error = 'No file selected.';
			return;
		}

		isLoading = true;
		error = null;
		successMessage = null;

		const formData = new FormData();
		formData.append('character_card', selectedFile); // Backend expects 'character_card'

		try {
			const newCharacter = await apiClient.uploadCharacter(formData);
			successMessage = `Character "${newCharacter.name}" uploaded successfully!`;
			selectedFile = null; // Clear selection after successful upload
			if (onUploadSuccess) {
				onUploadSuccess(); // Notify parent component (e.g., CharacterList)
			}
		} catch (err: any) {
			console.error('Upload failed:', err);
			error = err.message || 'An unknown error occurred during upload.';
		} finally {
			isLoading = false;
		}
	};

	// --- Drag and Drop Handlers ---
	const handleDragOver = (event: DragEvent) => {
		event.preventDefault(); // Necessary to allow drop
		dragOver = true;
	};

	const handleDragLeave = () => {
		dragOver = false;
	};

	const handleDrop = (event: DragEvent) => {
		event.preventDefault();
		dragOver = false;
		if (event.dataTransfer?.files && event.dataTransfer.files.length > 0) {
			const file = event.dataTransfer.files[0];
			if (file.type === 'image/png') {
				selectedFile = file;
				error = null;
				successMessage = null;
			} else {
				selectedFile = null;
				error = 'Invalid file type. Please drop a PNG file.';
				successMessage = null;
			}
		}
	};

</script>

<div role="button" tabindex="0" class="border border-dashed rounded-lg p-6 text-center"
	 class:border-primary={dragOver}
	 ondragover={handleDragOver}
	 ondragleave={handleDragLeave}
	 ondrop={handleDrop}
>
	<Upload class="mx-auto h-12 w-12 text-muted-foreground" />
	<Label for="character-card-input" class="mt-4 block text-sm font-medium text-foreground">
		Character Card (.png)
	</Label>
	<p class="mt-1 text-xs text-muted-foreground">
		Drag & drop a PNG file here, or click to select
	</p>
	<Input
		id="character-card-input"
		type="file"
		accept=".png"
		class="sr-only"
		onchange={handleFileChange}
		disabled={isLoading}
	/>

	{#if selectedFile}
		<p class="mt-2 text-sm text-foreground">Selected: {selectedFile.name}</p>
	{/if}

	{#if error}
		<Alert.Root variant="destructive" class="mt-4 text-left">
			<AlertCircle class="h-4 w-4" />
			<Alert.Title>Upload Failed</Alert.Title>
			<Alert.Description>{error}</Alert.Description>
		</Alert.Root>
	{/if}

	{#if successMessage}
		<Alert.Root variant="default" class="mt-4 text-left bg-green-100 dark:bg-green-900 border-green-300 dark:border-green-700">
			<CheckCircle2 class="h-4 w-4 text-green-700 dark:text-green-300" />
			<Alert.Title class="text-green-800 dark:text-green-200">Success</Alert.Title>
			<Alert.Description class="text-green-700 dark:text-green-300">{successMessage}</Alert.Description>
		</Alert.Root>
	{/if}

	<Button
		class="mt-6 w-full"
		onclick={handleUpload}
		disabled={!selectedFile || isLoading}
	>
		{#if isLoading}
			<Loader2 class="mr-2 h-4 w-4 animate-spin" />
			Uploading...
		{:else}
			<Upload class="mr-2 h-4 w-4" />
			Upload
		{/if}
	</Button>
</div>