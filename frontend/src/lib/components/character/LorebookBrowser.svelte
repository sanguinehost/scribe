<script lang="ts">
	import { onMount } from 'svelte';
	import { apiClient } from '$lib/api';
	import type { Lorebook } from '$lib/types';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import * as Card from '$lib/components/ui/card';
	import { BookOpen, ChevronRight, Loader2, Search } from 'lucide-svelte';
	import { toast } from 'svelte-sonner';

	interface Props {
		onSelect?: (lorebook: Lorebook, mode: 'link' | 'import') => void;
	}

	let { onSelect }: Props = $props();

	let lorebooks = $state<Lorebook[]>([]);
	let isLoading = $state(true);
	let searchQuery = $state('');
	let selectedLorebookId = $state<string | null>(null);

	const filteredLorebooks = $derived(
		lorebooks.filter(
			(lb) =>
				lb.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
				lb.description?.toLowerCase().includes(searchQuery.toLowerCase())
		)
	);

	const selectedLorebook = $derived(lorebooks.find((lb) => lb.id === selectedLorebookId) || null);

	onMount(async () => {
		await loadLorebooks();
	});

	async function loadLorebooks() {
		isLoading = true;
		const result = await apiClient.getLorebooks();

		if (result.isOk()) {
			lorebooks = result.value;
		} else {
			toast.error('Failed to load lorebooks');
			console.error('Failed to load lorebooks:', result.error);
		}

		isLoading = false;
	}

	function handleSelectLorebook(lorebookId: string) {
		selectedLorebookId = lorebookId === selectedLorebookId ? null : lorebookId;
	}

	function handleLinkLorebook() {
		if (selectedLorebook && onSelect) {
			onSelect(selectedLorebook, 'link');
			toast.success(`Linked lorebook: ${selectedLorebook.name}`);
		}
	}

	function handleImportLorebook() {
		if (selectedLorebook && onSelect) {
			onSelect(selectedLorebook, 'import');
			toast.success(`Imported entries from: ${selectedLorebook.name}`);
		}
	}
</script>

<div class="space-y-4">
	<!-- Search -->
	<div class="space-y-2">
		<Label for="lorebook-search">Search Lorebooks</Label>
		<div class="relative">
			<Search class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
			<Input
				id="lorebook-search"
				bind:value={searchQuery}
				placeholder="Search by name or description..."
				class="pl-9"
			/>
		</div>
	</div>

	<!-- Loading State -->
	{#if isLoading}
		<div class="flex items-center justify-center py-12">
			<Loader2 class="h-8 w-8 animate-spin text-muted-foreground" />
		</div>
	{:else if filteredLorebooks.length === 0}
		<!-- Empty State -->
		<Card.Root class="border-dashed">
			<Card.Content class="flex flex-col items-center justify-center py-12 text-center">
				<BookOpen class="mb-4 h-12 w-12 text-muted-foreground" />
				<h3 class="mb-2 text-lg font-semibold">
					{searchQuery ? 'No matching lorebooks' : 'No lorebooks yet'}
				</h3>
				<p class="mb-4 text-sm text-muted-foreground">
					{searchQuery
						? 'Try a different search term'
						: 'Create standalone lorebooks to share worldbuilding across characters'}
				</p>
				{#if !searchQuery}
					<Button variant="outline" onclick={() => {}}>
						Create First Lorebook
						<ChevronRight class="ml-2 h-4 w-4" />
					</Button>
				{/if}
			</Card.Content>
		</Card.Root>
	{:else}
		<!-- Lorebook List -->
		<div class="space-y-3">
			{#each filteredLorebooks as lorebook (lorebook.id)}
				<Card.Root
					class="cursor-pointer transition-colors hover:bg-muted/50 {selectedLorebookId ===
					lorebook.id
						? 'border-primary bg-primary/5'
						: ''}"
					onclick={() => handleSelectLorebook(lorebook.id)}
				>
					<Card.Content class="p-4">
						<div class="flex items-start gap-3">
							<div class="mt-1">
								<BookOpen
									class="h-5 w-5 {selectedLorebookId === lorebook.id
										? 'text-primary'
										: 'text-muted-foreground'}"
								/>
							</div>
							<div class="flex-1">
								<h3 class="font-semibold">
									{lorebook.name || 'Unnamed Lorebook'}
								</h3>
								{#if lorebook.description}
									<p class="mt-1 text-sm text-muted-foreground">
										{lorebook.description}
									</p>
								{/if}
								<div class="mt-2 flex gap-4 text-xs text-muted-foreground">
									{#if lorebook.is_public}
										<span class="text-green-600 dark:text-green-400">Public</span>
									{:else}
										<span>Private</span>
									{/if}
								</div>
							</div>
						</div>
					</Card.Content>
				</Card.Root>
			{/each}
		</div>

		<!-- Selection Info & Actions -->
		{#if selectedLorebook}
			<Card.Root class="border-primary bg-primary/5">
				<Card.Content class="p-4">
					<h4 class="mb-2 font-semibold">Selected: {selectedLorebook.name}</h4>
					<p class="mb-4 text-sm text-muted-foreground">
						Choose how to use this lorebook with your character:
					</p>
					<div class="grid grid-cols-2 gap-2">
						<Button variant="default" onclick={handleLinkLorebook} class="flex-1">
							Link Lorebook
						</Button>
						<Button variant="outline" onclick={handleImportLorebook} class="flex-1">
							Import Entries
						</Button>
					</div>
					<div class="mt-3 space-y-2 text-xs text-muted-foreground">
						<p><strong>Link:</strong> Reference the lorebook. Updates sync automatically.</p>
						<p>
							<strong>Import:</strong> Copy entries into character. Creates standalone version.
						</p>
					</div>
				</Card.Content>
			</Card.Root>
		{/if}
	{/if}
</div>
