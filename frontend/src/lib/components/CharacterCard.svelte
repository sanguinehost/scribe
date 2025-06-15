<script lang="ts">
	import { Card, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { Button } from '$lib/components/ui/button';
	import {
		AlertDialog,
		AlertDialogAction,
		AlertDialogCancel,
		AlertDialogContent,
		AlertDialogDescription,
		AlertDialogFooter,
		AlertDialogHeader,
		AlertDialogTitle
	} from '$lib/components/ui/alert-dialog';
	import PencilEdit from '$lib/components/icons/pencil-edit.svelte';
	import TrashIcon from '$lib/components/icons/trash.svelte';
	import { createEventDispatcher } from 'svelte';
	import { apiClient } from '$lib/api';
	import { env } from '$env/dynamic/public';

	import type { CharacterDataForClient } from '$lib/types';

	let {
		character,
		isSelected = false
	}: {
		character: CharacterDataForClient;
		isSelected?: boolean;
	} = $props();

	const dispatch = createEventDispatcher();

	let isDeleting = $state(false);
	let showDeleteDialog = $state(false);

	function handleClick() {
		dispatch('select', { characterId: character.id });
	}

	function handleEdit(e: Event) {
		e.stopPropagation(); // Prevent card selection when clicking edit
		dispatch('edit', { characterId: character.id });
	}

	function handleDeleteClick(e: Event) {
		e.stopPropagation(); // Prevent card selection when clicking delete
		showDeleteDialog = true;
	}

	async function handleDelete() {
		isDeleting = true;
		try {
			const result = await apiClient.deleteCharacter(character.id);
			if (result.isOk()) {
				dispatch('delete', { characterId: character.id });
				showDeleteDialog = false;
			} else {
				console.error('Failed to delete character:', result.error);
				// TODO: Show error toast
			}
		} catch (error) {
			console.error('Error deleting character:', error);
		} finally {
			isDeleting = false;
		}
	}

	// Simple function to get first letter for fallback avatar
	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Function to create a short snippet from description or greeting
	function getDescriptionSnippet(description: string | null, greeting: string | null): string {
		let text = description || greeting || 'No description available.';
		// Substitute {{char}} for display in the card.
		text = text.replace(/\{\{char\}\}/g, character.name);
		const maxLength = 80; // Adjust as needed
		return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
	}

	// The backend populates character.avatar with the image URL (/api/characters/{id}/assets/{asset_id})
	// Append width and height query parameters for server-side resizing
	// In production, we need to prepend the API URL if it's not already included
	const avatarSrc = $derived.by(() => {
		if (!character.avatar) return null;
		
		// If avatar already has a full URL, use it as-is
		if (character.avatar.startsWith('http://') || character.avatar.startsWith('https://')) {
			return `${character.avatar}?width=56&height=56`;
		}
		
		// Otherwise, prepend the API URL
		// Use env variable for API URL in production
		const apiBaseUrl = (env.PUBLIC_API_URL || '').trim();
		return `${apiBaseUrl}${character.avatar}?width=56&height=56`;
	});
</script>

<Card
	class="group/card relative cursor-pointer rounded-lg border-border/40 transition-all hover:border-primary hover:shadow-lg {isSelected
		? 'border-primary ring-1 ring-primary'
		: 'hover:bg-muted/50'}"
	onclick={handleClick}
	onkeydown={(e) => e.key === 'Enter' && handleClick()}
	tabindex={0}
	role="button"
	aria-pressed={isSelected}
	aria-label={`Select character ${character.name}`}
>
	<CardHeader class="flex flex-row items-center gap-2 p-3">
		<Avatar class="h-14 w-14">
			{#if avatarSrc}
				<AvatarImage src={avatarSrc} alt={character.name} />
			{/if}
			<AvatarFallback>{getInitials(character.name)}</AvatarFallback>
		</Avatar>
		<div class="flex-1 overflow-hidden">
			<CardTitle class="pt-1 text-base font-semibold">{character.name}</CardTitle>
			<CardDescription class="truncate text-sm text-muted-foreground">
				{getDescriptionSnippet(character.description ?? null, character.greeting ?? null)}
			</CardDescription>
		</div>
	</CardHeader>
	<div
		class="absolute right-0.5 top-0.5 flex gap-0 opacity-0 transition-opacity focus-within:opacity-100 group-hover/card:opacity-100"
	>
		<Button
			variant="ghost"
			size="icon"
			class="h-5 w-5"
			onclick={handleEdit}
			aria-label={`Edit character ${character.name}`}
		>
			<PencilEdit class="h-2.5 w-2.5" />
		</Button>
		<Button
			variant="ghost"
			size="icon"
			class="h-5 w-5 text-destructive hover:text-destructive"
			onclick={handleDeleteClick}
			aria-label={`Delete character ${character.name}`}
		>
			<TrashIcon class="h-2.5 w-2.5" />
		</Button>
	</div>
</Card>

<AlertDialog bind:open={showDeleteDialog}>
	<AlertDialogContent>
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Character</AlertDialogTitle>
			<AlertDialogDescription>
				Are you sure you want to delete "{character.name}"? This action cannot be undone.
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={handleDelete}
				disabled={isDeleting}
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
			>
				{isDeleting ? 'Deleting...' : 'Delete'}
			</AlertDialogAction>
		</AlertDialogFooter>
	</AlertDialogContent>
</AlertDialog>
