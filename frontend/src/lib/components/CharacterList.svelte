<script lang="ts">
	import { createEventDispatcher, untrack } from 'svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import type { ScribeCharacter as Character } from '$lib/types';
	import { getIsAuthenticated, getIsAuthReady } from '$lib/auth.svelte';
	import CharacterCard from './CharacterCard.svelte';
	import CharacterEditor from './CharacterEditor.svelte';
	import CharacterCreator from './CharacterCreator.svelte';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import PlusIcon from './icons/plus.svelte';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { slideAndFade } from '$lib/utils/transitions';

	let characters = $state<Character[]>([]);
	let isLoading = $state(true);
	let error = $state<string | null>(null);
	let selectedCharacterId = $state<string | null>(null); // To track selection state for cards
	let editingCharacter = $state<Character | undefined>(undefined); // The character being edited
	let showEditor = $state(false);
	let showCreator = $state(false);

	const dispatch = createEventDispatcher();

	// Function to fetch characters, reusable for initial load and refresh
	async function fetchCharacters() {
		isLoading = true;
		error = null;
		try {
			const result = await _apiClient.getCharacters();

			if (result.isOk()) {
				characters = result.value;
				error = null; // Clear previous errors on success
			} else {
				console.error('Error fetching characters:', result.error);
				error = 'Failed to load characters. Please try again later.';
				characters = []; // Clear characters on error
			}
		} catch (e: unknown) {
			console.error('Failed to fetch characters:', e);
			error = 'Failed to load characters. Please try again later.';
			characters = []; // Clear characters on error
		} finally {
			isLoading = false;
		}
	}

	// Only fetch once when auth is ready
	let hasFetched = $state(false);

	// CRITICAL FIX: Use $effect to reactively track auth state
	// This creates explicit subscriptions that trigger when auth becomes ready
	// Use untrack() to prevent state modifications from creating new reactive dependencies
	$effect(() => {
		const authReady = getIsAuthReady();
		const authenticated = getIsAuthenticated();

		// Initial fetch when auth becomes ready
		if (!hasFetched && authReady && authenticated) {
			console.log('[CharacterList] Auth ready detected, fetching characters');
			// Use untrack to prevent infinite loops from state modifications inside fetchCharacters
			untrack(() => {
				fetchCharacters();
				hasFetched = true;
			});
		}
	});

	// Expose a refresh function for the parent component
	export async function refresh() {
		await fetchCharacters();
	}

	// Correct single definition of handleSelect
	function handleSelect(_event: CustomEvent<{ characterId: string }>) {
		selectedCharacterId = _event.detail.characterId;
		dispatch('selectCharacter', { characterId: selectedCharacterId });
	}

	function handleUploadClick() {
		dispatch('uploadCharacter');
	}

	function handleEdit(_event: CustomEvent<{ characterId: string }>) {
		const characterId = _event.detail.characterId;
		editingCharacter = characters.find((c) => c.id === characterId);
		showEditor = true;
	}

	function handleDelete(_event: CustomEvent<{ characterId: string }>) {
		// Refresh the character list after successful deletion
		fetchCharacters();
	}

	// Handle when editor closes to refresh the character list
	$effect(() => {
		// Watch for editor closing
		if (!showEditor && editingCharacter) {
			// Use untrack to prevent infinite loops from state modifications
			untrack(() => {
				// Refresh character list after editing
				fetchCharacters();
				editingCharacter = undefined;
			});
		}
	});

	function handleCreateClick() {
		showCreator = true;
	}

	function handleCharacterCreated() {
		// Refresh the character list
		fetchCharacters();
	}
</script>

<div class="flex h-full flex-col">
	<div class="flex items-center justify-between border-b border-border/40 bg-muted/10 p-2 pb-2">
		<h2 class="px-2 text-lg font-semibold tracking-tight">Characters</h2>
		<div class="flex gap-1">
			<ButtonComponent
				variant="ghost"
				size="icon"
				onclick={handleCreateClick}
				aria-label="Create Character"
				title="Create Character"
			>
				<PlusIcon class="h-5 w-5" />
			</ButtonComponent>
			<ButtonComponent
				variant="ghost"
				size="icon"
				onclick={handleUploadClick}
				aria-label="Upload Character"
				title="Upload Character Card"
			>
				<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width="2"
						d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
					/>
				</svg>
			</ButtonComponent>
		</div>
	</div>

	<div class="flex-1 space-y-2 overflow-y-auto p-2">
		{#if isLoading}
			<!-- Loading Skeletons -->
			{#each Array(3) as _}
				<div class="flex items-center space-x-4 p-2">
					<Skeleton class="h-12 w-12 rounded-full" />
					<div class="flex-1 space-y-2">
						<Skeleton class="h-4 w-3/4" />
						<Skeleton class="h-4 w-1/2" />
					</div>
				</div>
			{/each}
		{:else if error}
			<p class="p-4 text-sm text-destructive">{error}</p>
		{:else if characters.length === 0}
			<p class="p-4 text-sm text-muted-foreground">
				No characters found. Upload one to get started!
			</p>
		{:else}
			{#each characters as character (character.id)}
				{#key character.id}
					<div
						in:slideAndFade={{ y: 20, duration: 300 }}
						out:slideAndFade={{ y: -20, duration: 200 }}
					>
						<CharacterCard
							{character}
							isSelected={selectedCharacterId === character.id}
							on:select={handleSelect}
							on:edit={handleEdit}
							on:delete={handleDelete}
						/>
					</div>
				{/key}
			{/each}
		{/if}
	</div>
</div>

<CharacterEditor character={editingCharacter} bind:open={showEditor} />

<CharacterCreator bind:open={showCreator} on:created={handleCharacterCreated} />
