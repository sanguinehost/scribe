<!-- frontend/src/routes/characters/+page.svelte -->
<script lang="ts">
	import CharacterList from '$lib/components/characters/CharacterList.svelte';
	import CharacterUploader from '$lib/components/characters/CharacterUploader.svelte';
	import { authStore } from '$lib/stores/authStore'; // Assuming layout handles redirect, but good for conditional rendering if needed
	import { Separator } from '$lib/components/ui/separator';

	let characterListComp: CharacterList; // Reference to the CharacterList component instance

	// Function to refresh the list when the uploader signals success
	function handleUploadSuccess() {
		if (characterListComp) {
			characterListComp.refreshList();
		} else {
			console.warn('CharacterList component reference not available to refresh.');
		}
	}

	// Note: Authentication is primarily handled by the root +layout.svelte,
	// which should redirect unauthenticated users away from this page.
	// We assume the user is authenticated if they reach this page.
</script>

<svelte:head>
	<title>Characters - Scribe</title>
</svelte:head>

<div class="container mx-auto p-4 space-y-6">
	<h1 class="text-3xl font-bold">Manage Characters</h1>

	{#if $authStore.isAuthenticated}
		<!-- Character Uploader Section -->
		<CharacterUploader on:uploadSuccess={handleUploadSuccess} />

		<Separator class="my-6" />

		<!-- Character List Section -->
		<div>
			<h2 class="text-2xl font-semibold mb-4">Your Characters</h2>
			<CharacterList bind:this={characterListComp} />
		</div>
	{:else}
		<!-- This should ideally not be reached if layout auth works correctly -->
		<p class="text-center text-muted-foreground py-8">
			Please log in to manage your characters.
		</p>
	{/if}
</div>