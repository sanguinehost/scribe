<script lang="ts">
	import type { LorebookEntry } from '$lib/types/character';
	import { characterStore } from '$lib/stores/character.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import Button from '$lib/components/ui/button/button.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import * as Card from '$lib/components/ui/card';
	import * as Alert from '$lib/components/ui/alert';
	import { Check, X, AlertCircle, Sparkles } from '@lucide/svelte';
	import { Badge } from '$lib/components/ui/badge';

	const { character } = $derived(characterStore);

	interface Props {
		open: boolean;
		entries: LorebookEntry[];
		onapprove?: (entries: LorebookEntry[]) => void;
		oncancel?: () => void;
	}

	let { open = $bindable(), entries, onapprove, oncancel }: Props = $props();

	// Create editable copies of entries with approval status
	// eslint-disable-next-line svelte/prefer-writable-derived
	let editableEntries = $state<Array<LorebookEntry & { approved: boolean }>>([]);

	// Initialize editable entries when entries prop changes
	$effect(() => {
		editableEntries = entries.map((entry) => ({
			...entry,
			approved: true // All approved by default
		}));
	});

	// Check if entry name is a duplicate
	function isDuplicate(entryName: string | undefined): boolean {
		if (!entryName || !character?.data.character_book?.entries) return false;
		const nameLower = entryName.toLowerCase().trim();
		return character.data.character_book.entries.some(
			(e) => e.name?.toLowerCase().trim() === nameLower
		);
	}

	// Check if an entry might have issues
	function hasWarnings(entry: LorebookEntry): boolean {
		const contentLower = entry.content.toLowerCase();
		return (
			isDuplicate(entry.name) ||
			entry.content.length < 100 ||
			contentLower.startsWith('generate') ||
			contentLower.includes('based on')
		);
	}

	// Get warning message for an entry
	function getWarningMessage(entry: LorebookEntry): string {
		if (isDuplicate(entry.name)) {
			return `An entry named "${entry.name}" already exists. Consider renaming or rejecting this entry.`;
		}
		const contentLower = entry.content.toLowerCase();
		if (contentLower.startsWith('generate') || contentLower.includes('based on')) {
			return 'This entry may contain placeholder text instead of actual content. Please review and edit.';
		}
		if (entry.content.length < 100) {
			return 'This entry has very short content. Consider adding more detail.';
		}
		return 'This entry may have issues. Please review.';
	}

	function handleApprove() {
		const approvedEntries = editableEntries
			.filter((e) => e.approved)
			.map((e) => {
				const { approved, ...entry } = e;
				return entry as LorebookEntry;
			});

		onapprove?.(approvedEntries);
		open = false;
	}

	function handleCancel() {
		oncancel?.();
		open = false;
	}

	function toggleEntryApproval(index: number) {
		editableEntries[index].approved = !editableEntries[index].approved;
	}

	function addKeyword(index: number) {
		editableEntries[index].keys.push('');
	}

	function removeKeyword(entryIndex: number, keyIndex: number) {
		editableEntries[entryIndex].keys.splice(keyIndex, 1);
	}

	const approvedCount = $derived(editableEntries.filter((e) => e.approved).length);
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="flex max-h-[90vh] max-w-4xl flex-col overflow-hidden">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<Sparkles class="h-5 w-5 text-primary" />
				Preview Generated Lorebook Entries
			</Dialog.Title>
			<Dialog.Description>
				Review and edit the {entries.length} generated lorebook
				{entries.length === 1 ? 'entry' : 'entries'} before adding them to your character.
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex-1 space-y-4 overflow-y-auto pr-2">
			{#if editableEntries.length === 0}
				<Alert.Root>
					<AlertCircle class="h-4 w-4" />
					<Alert.Title>No Entries</Alert.Title>
					<Alert.Description>No lorebook entries were generated.</Alert.Description>
				</Alert.Root>
			{:else}
				{#each editableEntries as entry, index (index)}
					<Card.Root class={entry.approved ? '' : 'opacity-50'}>
						<Card.Header>
							<div class="flex items-start justify-between gap-2">
								<div class="flex-1">
									<Label for="entry-name-{index}">Entry Name</Label>
									<Input
										id="entry-name-{index}"
										bind:value={entry.name}
										placeholder="Entry name..."
										disabled={!entry.approved}
									/>
								</div>
								<Button
									variant={entry.approved ? 'default' : 'outline'}
									size="sm"
									onclick={() => toggleEntryApproval(index)}
									class="mt-6"
								>
									{#if entry.approved}
										<Check class="mr-1 h-4 w-4" />
										Approved
									{:else}
										<X class="mr-1 h-4 w-4" />
										Rejected
									{/if}
								</Button>
							</div>

							{#if hasWarnings(entry)}
								<Alert.Root variant="destructive" class="mt-2">
									<AlertCircle class="h-4 w-4" />
									<Alert.Title>
										{isDuplicate(entry.name) ? 'Duplicate Entry' : 'Warning'}
									</Alert.Title>
									<Alert.Description>
										{getWarningMessage(entry)}
									</Alert.Description>
								</Alert.Root>
							{/if}
						</Card.Header>

						<Card.Content class="space-y-4">
							<!-- Content -->
							<div>
								<Label for="entry-content-{index}">Content</Label>
								<Textarea
									id="entry-content-{index}"
									bind:value={entry.content}
									placeholder="Lorebook entry content..."
									rows={6}
									disabled={!entry.approved}
								/>
								<p class="mt-1 text-xs text-muted-foreground">
									{entry.content.length} characters
								</p>
							</div>

							<!-- Keywords -->
							<div>
								<div class="mb-2 flex items-center justify-between">
									<Label>Keywords</Label>
									<Button
										variant="ghost"
										size="sm"
										onclick={() => addKeyword(index)}
										disabled={!entry.approved}
									>
										+ Add Keyword
									</Button>
								</div>
								<div class="flex flex-wrap gap-2">
									{#each entry.keys as _keyword, keyIndex (keyIndex)}
										<div class="flex items-center gap-1">
											<Input
												bind:value={entry.keys[keyIndex]}
												placeholder="keyword"
												class="w-32"
												disabled={!entry.approved}
											/>
											<Button
												variant="ghost"
												size="icon"
												onclick={() => removeKeyword(index, keyIndex)}
												disabled={!entry.approved}
											>
												<X class="h-4 w-4" />
											</Button>
										</div>
									{/each}
								</div>
							</div>

							<!-- Metadata -->
							<div class="flex gap-4 text-sm text-muted-foreground">
								<div class="flex items-center gap-1">
									<Badge variant={entry.enabled ? 'default' : 'outline'}>
										{entry.enabled ? 'Enabled' : 'Disabled'}
									</Badge>
								</div>
							</div>
						</Card.Content>
					</Card.Root>
				{/each}
			{/if}
		</div>

		<Dialog.Footer class="flex items-center justify-between">
			<p class="text-sm text-muted-foreground">
				{approvedCount} of {entries.length}
				{entries.length === 1 ? 'entry' : 'entries'} approved
			</p>
			<div class="flex gap-2">
				<Button variant="outline" onclick={handleCancel}>Cancel</Button>
				<Button onclick={handleApprove} disabled={approvedCount === 0}>
					<Check class="mr-2 h-4 w-4" />
					Add {approvedCount}
					{approvedCount === 1 ? 'Entry' : 'Entries'}
				</Button>
			</div>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
