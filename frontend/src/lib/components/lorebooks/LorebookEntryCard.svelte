<script lang="ts">
	import type { LorebookEntry } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Trash, Edit, Eye, EyeOff, Zap } from 'lucide-svelte';

	interface Props {
		entry: LorebookEntry;
		onEdit?: (entry: LorebookEntry) => void;
		onDelete?: (entry: LorebookEntry) => void;
		onToggleEnabled?: (entry: LorebookEntry) => void;
	}

	let { entry, onEdit, onDelete, onToggleEnabled }: Props = $props();

	function handleEdit(event: Event) {
		event.stopPropagation();
		onEdit?.(entry);
	}

	function handleDelete(event: Event) {
		event.stopPropagation();
		onDelete?.(entry);
	}

	function handleToggleEnabled(event: Event) {
		event.stopPropagation();
		onToggleEnabled?.(entry);
	}

	function formatDate(dateStr: string) {
		return new Date(dateStr).toLocaleDateString();
	}

	function truncateContent(content: string | null | undefined, maxLength: number = 150) {
		if (!content) return '';
		if (content.length <= maxLength) return content;
		return content.substring(0, maxLength) + '...';
	}

	const keywordsList = entry.keys_text ? entry.keys_text.split(',').map(k => k.trim()).filter(k => k.length > 0) : [];
	
	const cardClass = `transition-opacity ${!entry.is_enabled ? 'opacity-60' : ''}`;
</script>

<Card class={cardClass}>
	<CardHeader>
		<div class="flex items-start justify-between">
			<div class="flex-1">
				<CardTitle class="flex items-center gap-2 text-base">
					{entry.entry_title}
					<div class="flex gap-1">
						{#if entry.is_constant}
							<Badge variant="secondary" class="text-xs">
								<Zap class="h-3 w-3 mr-1" />
								Constant
							</Badge>
						{/if}
						<Badge variant={entry.is_enabled ? 'default' : 'secondary'} class="text-xs">
							{#if entry.is_enabled}
								<Eye class="h-3 w-3 mr-1" />
								Enabled
							{:else}
								<EyeOff class="h-3 w-3 mr-1" />
								Disabled
							{/if}
						</Badge>
					</div>
				</CardTitle>
				
				{#if keywordsList.length > 0}
					<CardDescription class="mt-2">
						<span class="text-xs font-medium">Keywords:</span>
						<div class="flex flex-wrap gap-1 mt-1">
							{#each keywordsList.slice(0, 5) as keyword}
								<Badge variant="outline" class="text-xs">{keyword}</Badge>
							{/each}
							{#if keywordsList.length > 5}
								<Badge variant="outline" class="text-xs">+{keywordsList.length - 5} more</Badge>
							{/if}
						</div>
					</CardDescription>
				{/if}
			</div>
			
			<div class="flex gap-1 ml-2">
				{#if onToggleEnabled}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleToggleEnabled}
						class="h-8 w-8 p-0"
						aria-label={entry.is_enabled ? 'Disable entry' : 'Enable entry'}
					>
						{#if entry.is_enabled}
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
	</CardHeader>
	
	<CardContent>
		<div class="space-y-3">
			<!-- Content preview -->
			<div class="text-sm">
				<p class="text-muted-foreground leading-relaxed">
					{truncateContent(entry.content)}
				</p>
			</div>

			{#if entry.comment}
				<div class="text-xs text-muted-foreground bg-muted p-2 rounded">
					<span class="font-medium">Comment:</span> {entry.comment}
				</div>
			{/if}

			<!-- Metadata -->
			<div class="flex justify-between text-xs text-muted-foreground pt-2 border-t">
				<div class="flex gap-4">
					<span>Order: {entry.insertion_order}</span>
					<span>Position: {entry.placement_hint}</span>
				</div>
				<span>Updated: {formatDate(entry.updated_at)}</span>
			</div>
		</div>
	</CardContent>
</Card>