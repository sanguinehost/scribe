<script lang="ts">
	import type { Lorebook } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Plus, Upload } from 'lucide-svelte';
	import LorebookCard from './LorebookCard.svelte';

	interface Props {
		lorebooks: Lorebook[];
		isLoading?: boolean;
		onCreateNew?: () => void;
		onUpload?: () => void;
		onSelectLorebook?: (lorebook: Lorebook) => void;
		onEditLorebook?: (lorebook: Lorebook) => void;
		onDeleteLorebook?: (lorebook: Lorebook) => void;
		onExportLorebook?: (lorebook: Lorebook) => void;
	}

	let {
		lorebooks,
		isLoading = false,
		onCreateNew,
		onUpload,
		onSelectLorebook,
		onEditLorebook,
		onDeleteLorebook,
		onExportLorebook
	}: Props = $props();
</script>

<div class="space-y-4">
	<!-- Header with action buttons -->
	<div class="flex items-center justify-between">
		<h2 class="text-2xl font-bold">Lorebooks</h2>
		<div class="flex gap-2">
			{#if onUpload}
				<Button variant="outline" onclick={onUpload}>
					<Upload class="mr-2 h-4 w-4" />
					Upload
				</Button>
			{/if}
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="mr-2 h-4 w-4" />
					Create New
				</Button>
			{/if}
		</div>
	</div>

	<!-- Loading state -->
	{#if isLoading}
		<div class="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each Array(6) as _}
				<div class="animate-pulse">
					<div class="space-y-3 rounded-lg bg-muted p-6">
						<div class="h-4 rounded bg-muted-foreground/20"></div>
						<div class="h-3 w-3/4 rounded bg-muted-foreground/20"></div>
						<div class="space-y-2">
							<div class="h-2 rounded bg-muted-foreground/20"></div>
							<div class="h-2 w-1/2 rounded bg-muted-foreground/20"></div>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{:else if lorebooks.length === 0}
		<!-- Empty state -->
		<div class="py-12 text-center">
			<div class="mx-auto mb-4 h-24 w-24 text-muted-foreground">
				<svg class="h-full w-full" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path
						stroke-linecap="round"
						stroke-linejoin="round"
						stroke-width={1}
						d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
					/>
				</svg>
			</div>
			<h3 class="mb-2 text-lg font-medium text-muted-foreground">No lorebooks yet</h3>
			<p class="mb-4 text-sm text-muted-foreground">
				Create your first lorebook to start building your world's knowledge base.
			</p>
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="mr-2 h-4 w-4" />
					Create Your First Lorebook
				</Button>
			{/if}
		</div>
	{:else}
		<!-- Lorebook grid -->
		<div class="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each lorebooks as lorebook (lorebook.id)}
				<LorebookCard
					{lorebook}
					onSelect={onSelectLorebook}
					onEdit={onEditLorebook}
					onDelete={onDeleteLorebook}
					onExport={onExportLorebook}
				/>
			{/each}
		</div>
	{/if}
</div>
