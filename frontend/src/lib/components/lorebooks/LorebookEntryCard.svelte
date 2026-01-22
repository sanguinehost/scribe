<script lang="ts">
	import type { LorebookEntry } from '$lib/types';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import {
		Card,
		CardContent,
		CardDescription,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import { Badge as BadgeComponent } from '$lib/components/ui/badge';
	import { Trash, Edit, Eye, EyeOff, Zap } from 'lucide-svelte';

	interface Props {
		entry: LorebookEntry;
		onEdit?: (entry: LorebookEntry) => void;
		onDelete?: (entry: LorebookEntry) => void;
		onToggleEnabled?: (entry: LorebookEntry) => void;
	}

	let { entry, onEdit, onDelete, onToggleEnabled }: Props = $props();

	function handleEdit(_event: Event) {
		_event.stopPropagation();
		onEdit?.(entry);
	}

	function handleDelete(_event: Event) {
		_event.stopPropagation();
		onDelete?.(entry);
	}

	function handleToggleEnabled(_event: Event) {
		_event.stopPropagation();
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

	const keywordsList = $derived(
		entry.keys_text
			? entry.keys_text
					.split(',')
					.map((k) => k.trim())
					.filter((k) => k.length > 0)
			: []
	);
	const cardClass = $derived(`transition-opacity ${!entry.is_enabled ? 'opacity-60' : ''}`);
</script>

<Card class={cardClass}>
	<CardHeader>
		<div class="flex items-start justify-between">
			<div class="flex-1">
				<CardTitle class="flex items-center gap-2 text-base">
					{entry.entry_title}
					<div class="flex gap-1">
						{#if entry.is_constant}
							<BadgeComponent variant="secondary" class="text-xs">
								<Zap class="mr-1 h-3 w-3" />
								Constant
							</BadgeComponent>
						{/if}
						<BadgeComponent variant={entry.is_enabled ? 'default' : 'secondary'} class="text-xs">
							{#if entry.is_enabled}
								<Eye class="mr-1 h-3 w-3" />
								Enabled
							{:else}
								<EyeOff class="mr-1 h-3 w-3" />
								Disabled
							{/if}
						</BadgeComponent>
					</div>
				</CardTitle>

				{#if keywordsList.length > 0}
					<CardDescription class="mt-2">
						<span class="text-xs font-medium">Keywords:</span>
						<div class="mt-1 flex flex-wrap gap-1">
							{#each keywordsList.slice(0, 5) as keyword}
								<BadgeComponent variant="outline" class="text-xs">{keyword}</BadgeComponent>
							{/each}
							{#if keywordsList.length > 5}
								<BadgeComponent variant="outline" class="text-xs"
									>+{keywordsList.length - 5} more</BadgeComponent
								>
							{/if}
						</div>
					</CardDescription>
				{/if}
			</div>

			<div class="ml-2 flex gap-1">
				{#if onToggleEnabled}
					<ButtonComponent
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
					</ButtonComponent>
				{/if}
				{#if onEdit}
					<ButtonComponent
						variant="ghost"
						size="sm"
						onclick={handleEdit}
						class="h-8 w-8 p-0"
						aria-label="Edit entry"
					>
						<Edit class="h-4 w-4" />
					</ButtonComponent>
				{/if}
				{#if onDelete}
					<ButtonComponent
						variant="ghost"
						size="sm"
						onclick={handleDelete}
						class="h-8 w-8 p-0 text-destructive hover:text-destructive"
						aria-label="Delete entry"
					>
						<Trash class="h-4 w-4" />
					</ButtonComponent>
				{/if}
			</div>
		</div>
	</CardHeader>

	<CardContent>
		<div class="space-y-3">
			<!-- Content preview -->
			<div class="text-sm">
				<p class="leading-relaxed text-foreground">
					{truncateContent(entry.content)}
				</p>
			</div>

			<!-- Metadata -->
			<div class="flex justify-end border-t pt-2 text-xs text-muted-foreground">
				<span>Updated: {formatDate(entry.updated_at)}</span>
			</div>
		</div>
	</CardContent>
</Card>
