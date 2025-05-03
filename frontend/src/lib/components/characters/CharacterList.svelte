<script lang="ts">
	import { onMount } from 'svelte';
	import { apiClient } from '$lib/services/apiClient';
	import type { Character } from '$lib/services/apiClient';
	import CharacterCard from './CharacterCard.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { AlertCircle, Loader2 } from 'lucide-svelte';
	import { goto } from '$app/navigation'; // For navigation on select

	// --- State ---
	let characters = $state<Character[]>([]);
	let isLoading = $state(true);
	let error = $state<string | null>(null);
	let selectedCharacterId = $state<string | null>(null); // Track selected character

	// --- Fetching Logic ---
	const fetchCharacters = async () => {
		isLoading = true;
		error = null;
		try {
			characters = await apiClient.listCharacters();
		} catch (err: any) {
			console.error('Failed to load characters:', err);
			error = err.message || 'An unknown error occurred while fetching characters.';
		} finally {
			isLoading = false;
		}
	};

	// --- Lifecycle ---
	onMount(() => {
		fetchCharacters();
	});

	// --- Event Handlers ---
	const handleSelectCharacter = async (characterId: string) => {
		selectedCharacterId = characterId;
		console.log(`Character selected: ${characterId}`);
		try {
			// Create/get the chat session for the selected character
			const { sessionId } = await apiClient.createChatSession(characterId);
			console.log(`Obtained session ID: ${sessionId}. Navigating...`);
			// Navigate to the chat page using the obtained session ID
			await goto(`/chat/${sessionId}`);
		} catch (err) {
			console.error('Failed to initiate or navigate to chat session:', err);
			// TODO: Implement user-friendly error handling (e.g., show a toast notification)
			error = `Could not start chat with character: ${err instanceof Error ? err.message : 'Unknown error'}`;
		}
	};

	// --- Expose refresh function for parent components (like uploader) ---
	// Note: Svelte 5 runes don't have a direct 'export function' equivalent for component methods easily.
	// A common pattern is to pass down a callback or use a store/context if complex interaction is needed.
	// For simplicity here, we'll assume the parent page will trigger a re-render or call fetchCharacters
	// if needed after an upload. If direct method call is required, refactoring might be needed.
	// export const refresh = fetchCharacters; // This syntax is not standard for runes $state/$props

</script>

<div>
	{#if isLoading}
		<div class="flex items-center justify-center p-10 text-muted-foreground">
			<Loader2 class="mr-2 h-5 w-5 animate-spin" />
			<span>Loading Characters...</span>
		</div>
	{/if}

	{#if error}
		<Alert.Root variant="destructive" class="mb-4">
			<AlertCircle class="h-4 w-4" />
			<Alert.Title>Error Loading Characters</Alert.Title>
			<Alert.Description>{error}</Alert.Description>
		</Alert.Root>
	{/if}

	{#if !isLoading && !error}
		{#if characters.length === 0}
			<p class="text-center text-muted-foreground p-10">
				No characters found. Upload one to get started!
			</p>
		{:else}
			<div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
				{#each characters as character (character.id)}
					<button 
						type="button" 
						class="w-full text-left"
						onclick={() => handleSelectCharacter(character.id)}
						onkeydown={(e) => e.key === 'Enter' && handleSelectCharacter(character.id)}>
						<CharacterCard
							{character}
							isSelected={selectedCharacterId === character.id}
						/>
					</button>
				{/each}
			</div>
		{/if}
	{/if}
</div>