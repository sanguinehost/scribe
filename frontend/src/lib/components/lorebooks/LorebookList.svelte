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
					<Upload class="h-4 w-4 mr-2" />
					Upload
				</Button>
			{/if}
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="h-4 w-4 mr-2" />
					Create New
				</Button>
			{/if}
		</div>
	</div>

	<!-- Loading state -->
	{#if isLoading}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each Array(6) as _}
				<div class="animate-pulse">
					<div class="bg-muted rounded-lg p-6 space-y-3">
						<div class="h-4 bg-muted-foreground/20 rounded"></div>
						<div class="h-3 bg-muted-foreground/20 rounded w-3/4"></div>
						<div class="space-y-2">
							<div class="h-2 bg-muted-foreground/20 rounded"></div>
							<div class="h-2 bg-muted-foreground/20 rounded w-1/2"></div>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{:else if lorebooks.length === 0}
		<!-- Empty state -->
		<div class="text-center py-12">
			<div class="mx-auto h-24 w-24 text-muted-foreground mb-4">
				<svg class="h-full w-full" fill="none" viewBox="0 0 24 24" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width={1} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
				</svg>
			</div>
			<h3 class="text-lg font-medium text-muted-foreground mb-2">No lorebooks yet</h3>
			<p class="text-sm text-muted-foreground mb-4">
				Create your first lorebook to start building your world's knowledge base.
			</p>
			{#if onCreateNew}
				<Button onclick={onCreateNew}>
					<Plus class="h-4 w-4 mr-2" />
					Create Your First Lorebook
				</Button>
			{/if}
		</div>
	{:else}
		<!-- Lorebook grid -->
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
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