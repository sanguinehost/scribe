<script lang="ts">
	import { Card, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { createEventDispatcher } from 'svelte';

	export let character: {
		id: string;
		name: string;
		description: string | null;
		greeting: string | null;
		avatar_url: string | null; // Assuming backend provides a URL or path
	};
	export let isSelected: boolean = false;

	const dispatch = createEventDispatcher();

	function handleClick() {
		dispatch('select', { characterId: character.id });
	}

	// Simple function to get first letter for fallback avatar
	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Function to create a short snippet from description or greeting
	function getDescriptionSnippet(description: string | null, greeting: string | null): string {
		const text = description || greeting || 'No description available.';
		const maxLength = 80; // Adjust as needed
		return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
	}

	// Construct the avatar URL - assuming backend serves it relative to API base
	// TODO: Confirm the actual base path for character avatars if served by backend
	// For now, assume it's an absolute URL or handle relative path if needed.
	// If backend provides a relative path like '/images/char_id.png', prepend the API base URL.
	// Let's assume for now avatar_url is either absolute or null.
	const avatarSrc = character.avatar_url; // Direct use for now

</script>

<Card
	class="cursor-pointer transition-all hover:shadow-md hover:border-primary {isSelected
		? 'border-primary ring-2 ring-primary'
		: ''}"
	onclick={handleClick}
	onkeydown={(e) => e.key === 'Enter' && handleClick()}
	tabindex={0}
	role="button"
	aria-pressed={isSelected}
	aria-label={`Select character ${character.name}`}
>
	<CardHeader class="flex flex-row items-center gap-4 p-4">
		<Avatar class="h-12 w-12">
			{#if avatarSrc}
				<AvatarImage src={avatarSrc} alt={character.name} />
			{/if}
			<AvatarFallback>{getInitials(character.name)}</AvatarFallback>
		</Avatar>
		<div class="flex-1 overflow-hidden">
			<CardTitle class="text-lg truncate">{character.name}</CardTitle>
			<CardDescription class="text-sm truncate">
				{getDescriptionSnippet(character.description, character.greeting)}
			</CardDescription>
		</div>
	</CardHeader>
</Card>