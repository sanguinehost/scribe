<!-- frontend/src/lib/components/characters/CharacterCard.svelte -->
<script lang="ts">
	import type { Character } from '$lib/services/apiClient';
	import { getCharacterImageUrl } from '$lib/services/apiClient';
	import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { createEventDispatcher } from 'svelte'; // Add this import

	export let character: Character;

	const dispatch = createEventDispatcher<{ select: string }>(); // Create dispatcher with type hint

	$: imageUrl = getCharacterImageUrl(character.id);
	$: fallbackName = character.name.substring(0, 2).toUpperCase(); // Simple fallback for avatar

	function handleClick() {
// console.log(`Character clicked: ${character.id} - ${character.name}`); // Keep for debugging if needed, but commented out
		dispatch('select', character.id); // Dispatch the event with character ID
	}
</script>

<Card class="cursor-pointer hover:shadow-lg transition-shadow" on:click={handleClick}>
	<CardHeader class="flex flex-row items-center gap-4 p-4">
		<Avatar class="h-12 w-12">
			<AvatarImage src={imageUrl} alt={character.name} />
			<AvatarFallback>{fallbackName}</AvatarFallback>
		</Avatar>
		<div class="flex-1">
			<CardTitle class="text-lg">{character.name}</CardTitle>
			<!-- Optionally show a short description or greeting -->
			{#if character.greeting}
				<CardDescription class="text-sm truncate">{character.greeting}</CardDescription>
			{:else if character.description}
                <CardDescription class="text-sm truncate">{character.description}</CardDescription>
            {/if}
		</div>
	</CardHeader>
	<!-- CardContent could be used for more details if needed later -->
	<!-- <CardContent class="p-4 pt-0">
		<p class="text-sm text-muted-foreground truncate">{character.description || 'No description available.'}</p>
	</CardContent> -->
</Card>