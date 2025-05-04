<script lang="ts">
	import { onMount, createEventDispatcher } from 'svelte';
	import { goto } from '$app/navigation'; // Import goto for redirection
	import CharacterCard from './CharacterCard.svelte';
	import { Button } from '$lib/components/ui/button';
	import PlusIcon from './icons/plus.svelte';
	import { Skeleton } from '$lib/components/ui/skeleton';

	// Define the expected structure of a character from the API
	type Character = {
		id: string;
		name: string;
		description: string | null;
		greeting: string | null;
		avatar_url: string | null;
		// Add other relevant fields if needed based on API response
	};

	let characters: Character[] = [];
	let isLoading = true;
	let error: string | null = null;
	let selectedCharacterId: string | null = null; // To track selection state for cards

	const dispatch = createEventDispatcher();

	// Function to fetch characters, reusable for initial load and refresh
	async function fetchCharacters() { // Marked as async
		isLoading = true;
		error = null;
		try {
			// TODO: Replace with actual API endpoint call
			const response = await fetch('/api/characters'); // Assumes API is served from the same origin

			if (!response.ok) {
				// Check specifically for 401 Unauthorized
				if (response.status === 401) {
					console.log('Unauthorized access to characters, redirecting to signin.');
					await goto('/signin'); // Redirect to sign-in page
					// Optionally, you might want to stop further processing in this component
					// by setting isLoading = false and returning, though redirect handles it.
					return; // Stop execution after redirect starts
				}
				// For other errors, throw a generic error
				throw new Error(`HTTP error! status: ${response.status}`);
			}
			characters = await response.json();
			error = null; // Clear previous errors on success
		} catch (e: any) {
			// Avoid setting error state if redirection happened or is about to happen
			if (e instanceof Error && e.message.includes('401')) {
				// Error already handled by redirect, just log if needed
				console.error('Caught 401 during fetch, redirection initiated.');
			} else {
				console.error('Failed to fetch characters:', e);
				error = 'Failed to load characters. Please try again later.';
				characters = []; // Clear characters on error
			}
		} finally {
			// Only set isLoading to false if not redirecting
			// The redirect should handle the loading state implicitly
			if (!(error === null && characters.length === 0 && !isLoading)) { // Avoid flicker if redirecting
				             isLoading = false;
				        }
		}
	}

	onMount(async () => {
		await fetchCharacters(); // Call fetch function on mount
	}); // Correctly closed onMount

	// Expose a refresh function for the parent component
	export async function refresh() {
		await fetchCharacters();
	}

	// Correct single definition of handleSelect
	function handleSelect(event: CustomEvent<{ characterId: string }>) {
		selectedCharacterId = event.detail.characterId;
		dispatch('selectCharacter', { characterId: selectedCharacterId });
	}

	function handleUploadClick() {
		dispatch('uploadCharacter');
	}
</script>

<div class="flex flex-col h-full">
	<div class="p-2 flex justify-between items-center border-b">
		<h2 class="text-lg font-semibold px-2">Characters</h2>
		<Button variant="ghost" size="icon" onclick={handleUploadClick} aria-label="Upload Character">
			<PlusIcon class="h-5 w-5" />
		</Button>
	</div>

	<div class="flex-1 overflow-y-auto p-2 space-y-2">
		{#if isLoading}
			<!-- Loading Skeletons -->
			{#each Array(3) as _}
				<div class="flex items-center space-x-4 p-2">
					<Skeleton class="h-12 w-12 rounded-full" />
					<div class="space-y-2 flex-1">
						<Skeleton class="h-4 w-3/4" />
						<Skeleton class="h-4 w-1/2" />
					</div>
				</div>
			{/each}
		{:else if error}
			<p class="p-4 text-sm text-destructive">{error}</p>
		{:else if characters.length === 0}
			<p class="p-4 text-sm text-muted-foreground">No characters found. Upload one to get started!</p>
		{:else}
			{#each characters as character (character.id)}
				<CharacterCard
					{character}
					isSelected={selectedCharacterId === character.id}
					on:select={handleSelect}
				/>
			{/each}
		{/if}
	</div>
</div>