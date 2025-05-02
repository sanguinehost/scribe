<!-- frontend/src/lib/components/characters/CharacterUploader.svelte -->
<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { uploadCharacter } from '$lib/services/apiClient';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input'; // Using Input for file selection
	import { Alert, AlertDescription, AlertTitle } from '$lib/components/ui/alert';
	import { AlertCircle, CheckCircle, Loader2, Upload } from 'lucide-svelte';

	let selectedFile: File | null = null;
	let isUploading = false;
	let error: string | null = null;
	let successMessage: string | null = null;
	let fileInput: HTMLInputElement; // To programmatically clear the input

	const dispatch = createEventDispatcher();

	function handleFileChange(event: Event) {
		const target = event.target as HTMLInputElement;
		if (target.files && target.files.length > 0) {
			selectedFile = target.files[0];
			error = null; // Clear previous errors on new file selection
			successMessage = null; // Clear previous success messages
		} else {
			selectedFile = null;
		}
	}

	async function handleUpload() {
		if (!selectedFile) {
			error = 'Please select a PNG file to upload.';
			return;
		}

		if (selectedFile.type !== 'image/png') {
			error = 'Invalid file type. Only PNG files are accepted.';
			return;
		}

		isUploading = true;
		error = null;
		successMessage = null;

		const formData = new FormData();
		// The backend expects the file under the key 'character_card'
		formData.append('character_card', selectedFile, selectedFile.name);

		try {
			const newCharacter = await uploadCharacter(formData);
			successMessage = `Character "${newCharacter.name}" uploaded successfully!`;
			dispatch('uploadSuccess'); // Notify parent component
			selectedFile = null; // Clear selection after successful upload
            if (fileInput) {
                fileInput.value = ''; // Reset the file input visually
            }
		} catch (err: any) {
			console.error('Upload failed:', err);
			error = err.message || 'Failed to upload character. Please try again.';
		} finally {
			isUploading = false;
		}
	}
</script>

<div class="space-y-4 p-4 border rounded-lg">
	<h3 class="text-lg font-medium">Upload New Character Card</h3>
	<p class="text-sm text-muted-foreground">Select a PNG character card file to upload.</p>

	<div class="flex flex-col sm:flex-row gap-2 items-start">
		<Input
            bind:this={fileInput}
			type="file"
			accept="image/png"
			on:change={handleFileChange}
			disabled={isUploading}
			class="flex-grow"
		/>
		<Button on:click={handleUpload} disabled={!selectedFile || isUploading} class="w-full sm:w-auto">
			{#if isUploading}
				<Loader2 class="mr-2 h-4 w-4 animate-spin" /> Uploading...
			{:else}
				<Upload class="mr-2 h-4 w-4" /> Upload
			{/if}
		</Button>
	</div>

	{#if successMessage}
		<Alert variant="success">
			<CheckCircle class="h-4 w-4" />
			<AlertTitle>Success</AlertTitle>
			<AlertDescription>{successMessage}</AlertDescription>
		</Alert>
	{/if}

	{#if error}
		<Alert variant="destructive">
			<AlertCircle class="h-4 w-4" />
			<AlertTitle>Error</AlertTitle>
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}
</div>

<!-- Add success variant style if not already present -->
<style>
	/* Assuming you might need to add custom styles for variants like 'success' if not built-in */
	/* Check your shadcn-svelte setup or global CSS */
	:global(.dark [data-variant="success"]) {
		/* Example dark mode success styles */
		border-color: hsl(var(--success-border-dark));
		background-color: hsl(var(--success-bg-dark));
		color: hsl(var(--success-text-dark));
	}
	:global([data-variant="success"]) {
		/* Example light mode success styles */
		border-color: hsl(var(--success-border));
		background-color: hsl(var(--success-bg));
		color: hsl(var(--success-text));
	}
	/* Define --success variables in your global CSS or :root */
</style>