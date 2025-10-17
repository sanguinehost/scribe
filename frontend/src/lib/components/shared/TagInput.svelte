<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import { X } from '@lucide/svelte';

	interface Props {
		tags?: string[];
	}

	let { tags = [] }: Props = $props();

	const dispatch = createEventDispatcher<{ update: string[] }>();

	let inputValue = $state('');

	function addTag() {
		const trimmed = inputValue.trim();
		if (trimmed && !tags.includes(trimmed)) {
			const newTags = [...tags, trimmed];
			dispatch('update', newTags);
			inputValue = '';
		}
	}

	function removeTag(tag: string) {
		const newTags = tags.filter((t) => t !== tag);
		dispatch('update', newTags);
	}

	function handleKeyDown(e: KeyboardEvent) {
		if (e.key === 'Enter') {
			e.preventDefault();
			addTag();
		}
	}
</script>

<div class="space-y-2">
	<Input
		type="text"
		placeholder="Add a tag and press Enter"
		bind:value={inputValue}
		onkeydown={handleKeyDown}
	/>

	{#if tags.length > 0}
		<div class="flex flex-wrap gap-2">
			{#each tags as tag (tag)}
				<Badge variant="secondary" class="gap-1">
					{tag}
					<button
						type="button"
						class="ml-1 rounded-full hover:bg-muted"
						onclick={() => removeTag(tag)}
						aria-label="Remove tag"
					>
						<X class="h-3 w-3" />
					</button>
				</Badge>
			{/each}
		</div>
	{/if}
</div>
