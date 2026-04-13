<script lang="ts">
	import { Card, CardHeader, CardTitle, CardDescription } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
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
	import { apiClient as _apiClient } from '$lib/api';
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
			const result = await _apiClient.deleteCharacter(character.id);
			if (result.isOk()) {
				dispatch('delete', { characterId: character.id });
				showDeleteDialog = false;
			} else {
				console.error('Failed to delete character:', result.error);
				// TODO: Show error toast
			}
		} catch (_error) {
			console.error('Error deleting character:', _error);
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

	// Extract character primary color for accent strip (if extensions data exists)
	const charPrimaryColor = $derived.by(() => {
		try {
			const ext = (character as unknown as Record<string, unknown>)?.extensions;
			if (ext && typeof ext === 'object') {
				const visual = (ext as Record<string, unknown>)?.visual_metadata;
				if (visual && typeof visual === 'object') {
					return (visual as Record<string, string>)?.primary_color || undefined;
				}
			}
		} catch {
			// Extensions may not exist in this character card format
		}
		return undefined;
	});
</script>

<Card
	class="group/card relative cursor-pointer overflow-hidden rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm transition-all duration-300 hover:scale-[1.01] hover:border-primary/50 hover:bg-card/80 hover:shadow-lg {isSelected
		? 'border-primary shadow-md ring-1 ring-primary'
		: 'hover:bg-muted/40'}"
	onclick={handleClick}
	onkeydown={(e) => e.key === 'Enter' && handleClick()}
	tabindex={0}
	role="button"
	aria-pressed={isSelected}
	aria-label={`Select character ${character.name}`}
>
	<!-- Left accent strip -->
	{#if charPrimaryColor}
		<div
			class="absolute left-0 top-0 bottom-0 w-0.5 rounded-l-xl transition-all duration-300 group-hover/card:w-1"
			style="background-color: {charPrimaryColor};"
		></div>
	{/if}

	<CardHeader class="flex flex-row items-center gap-3 p-3">
		<Avatar class="h-12 w-12 rounded-xl">
			{#if avatarSrc}
				<AvatarImage src={avatarSrc} alt={character.name} class="rounded-xl" />
			{/if}
			<AvatarFallback class="rounded-xl">{getInitials(character.name)}</AvatarFallback>
		</Avatar>
		<div class="flex-1 overflow-hidden">
			<CardTitle class="pt-1 text-base font-semibold">{character.name}</CardTitle>
			<CardDescription class="truncate text-sm text-muted-foreground">
				{getDescriptionSnippet(character.description ?? null, character.greeting ?? null)}
			</CardDescription>
			{#if character.tags && character.tags.length > 0}
				<div class="mt-1 flex gap-1">
					{#each character.tags.slice(0, 2) as tag, i (i)}
						<span class="rounded-full bg-muted/50 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">{tag}</span>
					{/each}
				</div>
			{/if}
		</div>
	</CardHeader>
	<div
		class="absolute right-1 top-1 flex gap-0.5 opacity-0 transition-opacity focus-within:opacity-100 group-hover/card:opacity-100"
	>
		<ButtonComponent
			variant="ghost"
			size="icon"
			class="h-6 w-6"
			onclick={handleEdit}
			aria-label={`Edit character ${character.name}`}
		>
			<PencilEdit class="h-3.5 w-3.5" />
		</ButtonComponent>
		<ButtonComponent
			variant="ghost"
			size="icon"
			class="h-6 w-6 text-destructive hover:text-destructive"
			onclick={handleDeleteClick}
			aria-label={`Delete character ${character.name}`}
		>
			<TrashIcon class="h-3.5 w-3.5" />
		</ButtonComponent>
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
