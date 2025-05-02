<!-- frontend/src/lib/components/characters/CharacterList.svelte -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { listCharacters, createChatSession, type Character } from '$lib/services/apiClient'; // Add createChatSession
	import CharacterCard from './CharacterCard.svelte';
	import { AlertCircle, Loader2 } from 'lucide-svelte';
	import { Alert, AlertDescription, AlertTitle } from '$lib/components/ui/alert';
	import { goto } from '$app/navigation'; // Add goto for navigation

	let characters: Character[] = [];
	let isLoading = true;
	let error: string | null = null; // Error for loading list
	let isCreatingSession = false; // Loading state for session creation
	let sessionError: string | null = null; // Error for session creation

	async function loadCharacters() {
		isLoading = true;
		error = null;
		try {
			characters = await listCharacters();
		} catch (err: any) {
			console.error('Failed to load characters:', err);
			error = err.message || 'Failed to load characters. Please try again later.';
			characters = []; // Clear characters on error
		} finally {
			isLoading = false;
		}
	}

	// Public function to allow parent components to trigger a refresh
	export async function refreshList() {
		await loadCharacters();
	}

	onMount(() => {
		loadCharacters();
	});

	async function handleCharacterSelect(event: CustomEvent<string>) {
const characterId = event.detail;
		isCreatingSession = true;
		sessionError = null;
		console.log(`Selected character: ${characterId}`); // Debug log

		try {
			const { sessionId } = await createChatSession(characterId);
			console.log(`Created session: ${sessionId}`); // Debug log
			await goto(`/chat/${sessionId}`);
			// Navigation happens, component might unmount, no need to set isCreatingSession = false here
		} catch (err: any) {
			console.error('Failed to create chat session:', err);
			sessionError = err.message || 'Failed to start chat. Please try again.';
			isCreatingSession = false; // Reset loading state on error
		}
		// No finally block needed as success leads to navigation
	}
</script>

<div class="space-y-4">
	{#if isLoading}
		<div class="flex items-center justify-center text-muted-foreground py-8">
			<Loader2 class="mr-2 h-5 w-5 animate-spin" />
			<span>Loading characters...</span>
		</div>
	{:else if error}
		<Alert variant="destructive">
			<AlertCircle class="h-4 w-4" />
			<AlertTitle>Error</AlertTitle>
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{:else if characters.length === 0}
		<p class="text-center text-muted-foreground py-8">No characters found. Upload one to get started!</p>
	{:else}
		{#if sessionError}
			<Alert variant="destructive" class="my-4">
				<AlertCircle class="h-4 w-4" />
				<AlertTitle>Error Starting Chat</AlertTitle>
				<AlertDescription>{sessionError}</AlertDescription>
			</Alert>
		{/if}
		<div
			class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4"
			class:opacity-50={isCreatingSession}
			class:pointer-events-none={isCreatingSession}
		>
			{#each characters as character (character.id)}
				<CharacterCard {character} on:select={handleCharacterSelect} />
			{/each}
		</div>
	{/if}
</div>