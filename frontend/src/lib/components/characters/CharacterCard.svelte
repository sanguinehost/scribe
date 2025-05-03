<script lang="ts">
	import type { Character } from '$lib/services/apiClient';
	import { getCharacterImageUrl } from '$lib/services/apiClient';
	import * as Card from '$lib/components/ui/card';
	import * as Avatar from '$lib/components/ui/avatar';
	import { cn } from '$lib/utils'; // For conditional classes

	// --- Props ---
	let { character, isSelected = false }: { character: Character; isSelected?: boolean } = $props();

	// --- Computed ---
	const imageUrl = $derived(getCharacterImageUrl(character.id));
	const fallbackText = $derived(character.name.substring(0, 2).toUpperCase());
	// Simple description snippet logic (can be refined)
	const descriptionSnippet = $derived(
		character.description?.length > 100
			? character.description.substring(0, 97) + '...'
			: character.description ?? character.greeting ?? 'No description available.' // Use greeting as fallback
	);

	// --- Classes ---
	// Apply a primary border if selected
	const cardClasses = $derived(cn(
		'transition-all hover:shadow-md hover:scale-[1.02] cursor-pointer', // Base styles
		isSelected && 'border-primary ring-2 ring-primary ring-offset-2' // Selected styles
	));

</script>

<Card.Root class={cardClasses}>
	<Card.Header class="flex flex-row items-center gap-4 pb-2">
		<Avatar.Root class="h-12 w-12">
			<Avatar.Image src={imageUrl} alt={character.name} />
			<Avatar.Fallback>{fallbackText}</Avatar.Fallback>
		</Avatar.Root>
		<div class="flex-1">
			<Card.Title>{character.name}</Card.Title>
		</div>
	</Card.Header>
	<Card.Content>
		<p class="text-sm text-muted-foreground">{descriptionSnippet}</p>
	</Card.Content>
	<!-- Footer could be added later if needed for actions like 'Edit' or 'Delete' -->
	<!-- <Card.Footer>...</Card.Footer> -->
</Card.Root>