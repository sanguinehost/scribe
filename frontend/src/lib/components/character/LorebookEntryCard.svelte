<script lang="ts">
	import type { LorebookEntry } from '$lib/types/character';
	import Button from '$lib/components/ui/button/button.svelte';
	import * as Card from '$lib/components/ui/card';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import { Trash, Edit, Eye, EyeOff, Zap, ChevronDown, ChevronUp } from '@lucide/svelte';

	interface Props {
		entry: LorebookEntry;
		index: number;
		onEdit?: (entry: LorebookEntry, index: number) => void;
		onDelete?: (entry: LorebookEntry, index: number) => void;
		onToggleEnabled?: (entry: LorebookEntry, index: number) => void;
	}

	let { entry, index, onEdit, onDelete, onToggleEnabled }: Props = $props();

	let isExpanded = $state(false);

	function handleEdit(event: Event) {
		event.stopPropagation();
		onEdit?.(entry, index);
	}

	function handleDelete(event: Event) {
		event.stopPropagation();
		onDelete?.(entry, index);
	}

	function handleToggleEnabled(event: Event) {
		event.stopPropagation();
		onToggleEnabled?.(entry, index);
	}

	function truncateContent(content: string | null | undefined, maxLength: number = 150) {
		if (!content) return '';
		if (content.length <= maxLength) return content;
		return content.substring(0, maxLength) + '...';
	}

	const cardClass = $derived(`transition-opacity ${!entry.enabled ? 'opacity-60' : ''}`);
	const contentIsTruncated = $derived((entry.content?.length || 0) > 150);
	const displayContent = $derived(
		isExpanded ? entry.content || '' : truncateContent(entry.content)
	);
</script>

<Card.Root class={cardClass}>
	<Card.Header>
		<div class="flex items-start justify-between">
			<div class="flex-1">
				<Card.Title class="flex items-center gap-2 text-base">
					{entry.name || `Entry ${index + 1}`}
					<div class="flex gap-1">
						{#if entry.constant}
							<Badge variant="secondary" class="text-xs">
								<Zap class="mr-1 h-3 w-3" />
								Constant
							</Badge>
						{/if}
						<Badge variant={entry.enabled ? 'default' : 'secondary'} class="text-xs">
							{#if entry.enabled}
								<Eye class="mr-1 h-3 w-3" />
								Enabled
							{:else}
								<EyeOff class="mr-1 h-3 w-3" />
								Disabled
							{/if}
						</Badge>
					</div>
				</Card.Title>

				{#if entry.keys && entry.keys.length > 0}
					<Card.Description class="mt-2">
						<span class="text-xs font-medium">Keywords:</span>
						<div class="mt-1 flex flex-wrap gap-1">
							{#each entry.keys.slice(0, 5) as keyword}
								<Badge variant="outline" class="text-xs">{keyword}</Badge>
							{/each}
							{#if entry.keys.length > 5}
								<Badge variant="outline" class="text-xs">+{entry.keys.length - 5} more</Badge>
							{/if}
						</div>
					</Card.Description>
				{/if}
			</div>

			<div class="ml-2 flex gap-1">
				{#if onToggleEnabled}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleToggleEnabled}
						class="h-8 w-8 p-0"
						aria-label={entry.enabled ? 'Disable entry' : 'Enable entry'}
					>
						{#if entry.enabled}
							<EyeOff class="h-4 w-4" />
						{:else}
							<Eye class="h-4 w-4" />
						{/if}
					</Button>
				{/if}
				{#if onEdit}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleEdit}
						class="h-8 w-8 p-0"
						aria-label="Edit entry"
					>
						<Edit class="h-4 w-4" />
					</Button>
				{/if}
				{#if onDelete}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleDelete}
						class="h-8 w-8 p-0 text-destructive hover:text-destructive"
						aria-label="Delete entry"
					>
						<Trash class="h-4 w-4" />
					</Button>
				{/if}
			</div>
		</div>
	</Card.Header>

	<Card.Content>
		<div class="space-y-3">
			<!-- Content preview -->
			{#if contentIsTruncated}
				<button
					type="button"
					onclick={() => (isExpanded = !isExpanded)}
					class="group relative -m-2 mb-2 w-full cursor-pointer rounded-md p-2 text-left text-sm transition-colors hover:bg-muted/50"
					aria-expanded={isExpanded}
				>
					<p class="whitespace-pre-wrap pb-6 leading-relaxed text-foreground">
						{displayContent}
					</p>
					<div
						class="absolute bottom-2 right-2 rounded-full bg-background/80 p-1 opacity-0 backdrop-blur-sm transition-opacity group-hover:opacity-100"
					>
						{#if isExpanded}
							<ChevronUp class="h-4 w-4 text-muted-foreground" />
						{:else}
							<ChevronDown class="h-4 w-4 text-muted-foreground" />
						{/if}
					</div>
				</button>
			{:else}
				<div class="mb-2 text-sm">
					<p class="whitespace-pre-wrap leading-relaxed text-foreground">
						{displayContent}
					</p>
				</div>
			{/if}

			<!-- Metadata -->
			<div class="flex justify-between border-t pt-3 text-xs text-muted-foreground">
				<span>Order: {entry.insertion_order}</span>
				{#if entry.priority}
					<span>Priority: {entry.priority}</span>
				{/if}
			</div>
		</div>
	</Card.Content>
</Card.Root>
