<script lang="ts">
	import type { Lorebook } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Trash, Download, Edit, BookOpen } from 'lucide-svelte';

	interface Props {
		lorebook: Lorebook;
		onSelect?: (lorebook: Lorebook) => void;
		onEdit?: (lorebook: Lorebook) => void;
		onDelete?: (lorebook: Lorebook) => void;
		onExport?: (lorebook: Lorebook) => void;
	}

	let { lorebook, onSelect, onEdit, onDelete, onExport }: Props = $props();

	function handleSelect() {
		onSelect?.(lorebook);
	}

	function handleEdit(event: Event) {
		event.stopPropagation();
		onEdit?.(lorebook);
	}

	function handleDelete(event: Event) {
		event.stopPropagation();
		onDelete?.(lorebook);
	}

	function handleExport(event: Event) {
		event.stopPropagation();
		onExport?.(lorebook);
	}

	function formatDate(dateStr: string) {
		return new Date(dateStr).toLocaleDateString();
	}
</script>

<Card class="cursor-pointer hover:shadow-md transition-shadow" onclick={handleSelect}>
	<CardHeader>
		<div class="flex items-start justify-between">
			<div class="flex-1">
				<CardTitle class="flex items-center gap-2">
					<BookOpen class="h-5 w-5" />
					{lorebook.name}
				</CardTitle>
				{#if lorebook.description}
					<CardDescription class="mt-1">
						{lorebook.description}
					</CardDescription>
				{/if}
			</div>
			<div class="flex gap-1 ml-2">
				{#if onEdit}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleEdit}
						class="h-8 w-8 p-0"
						aria-label="Edit lorebook"
					>
						<Edit class="h-4 w-4" />
					</Button>
				{/if}
				{#if onExport}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleExport}
						class="h-8 w-8 p-0"
						aria-label="Export lorebook"
					>
						<Download class="h-4 w-4" />
					</Button>
				{/if}
				{#if onDelete}
					<Button
						variant="ghost"
						size="sm"
						onclick={handleDelete}
						class="h-8 w-8 p-0 text-destructive hover:text-destructive"
						aria-label="Delete lorebook"
					>
						<Trash class="h-4 w-4" />
					</Button>
				{/if}
			</div>
		</div>
	</CardHeader>
	<CardContent>
		<div class="text-sm text-muted-foreground space-y-1">
			<div class="flex justify-between">
				<span>Source:</span>
				<span>{lorebook.source_format}</span>
			</div>
			<div class="flex justify-between">
				<span>Visibility:</span>
				<span>{lorebook.is_public ? 'Public' : 'Private'}</span>
			</div>
			<div class="flex justify-between">
				<span>Created:</span>
				<span>{formatDate(lorebook.created_at)}</span>
			</div>
			{#if lorebook.updated_at !== lorebook.created_at}
				<div class="flex justify-between">
					<span>Updated:</span>
					<span>{formatDate(lorebook.updated_at)}</span>
				</div>
			{/if}
		</div>
	</CardContent>
</Card>