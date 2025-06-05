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

	let {
		character,
		isSelected = false
	}: {
		character: {
			id: string;
			name: string;
			description: string | null;
			greeting: string | null;
			avatar_url: string | null; // Assuming backend provides a URL or path
		};
		isSelected?: boolean;
	} = $props();

	const dispatch = createEventDispatcher();

	let isDeleting = false;
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
		<div class="flex gap-1 ml-auto">
			<Button
				variant="ghost"
				size="icon"
				class="h-8 w-8"
				onclick={handleEdit}
				aria-label={`Edit character ${character.name}`}
			>
				<PencilEdit class="h-4 w-4" />
			</Button>
			<Button
				variant="ghost"
				size="icon"
				class="h-8 w-8 text-destructive hover:text-destructive"
				onclick={handleDeleteClick}
				aria-label={`Delete character ${character.name}`}
			>
				<TrashIcon class="h-4 w-4" />
			</Button>
		</div>
	</CardHeader>
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