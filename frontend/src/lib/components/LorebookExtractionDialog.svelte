<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import { Label } from '$lib/components/ui/label';
	import { Select, SelectContent, SelectItem, SelectTrigger } from '$lib/components/ui/select';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import { apiClient } from '$lib/api';
	import type { Result } from 'neverthrow';
	import type { LorebookEntry } from '$lib/types';

	// ApiError type for proper neverthrow typing
	interface ApiError {
		message: string;
		statusCode?: number;
	}

	// Props
	interface Props {
		open: boolean;
		chatSessionId: string;
		messages: Array<{ role: string; content: string; index: number }>;
		lorebooks: Array<{ id: string; name: string }>;
		onOpenChange: (open: boolean) => void;
		onSuccess?: (entries: LorebookEntry[]) => void;
	}

	let {
		open = $bindable(),
		chatSessionId,
		messages,
		lorebooks,
		onOpenChange,
		onSuccess
	}: Props = $props();

	// State
	let selectedLorebookId = $state<string | undefined>(undefined);
	let selectedMessageIndices = $state<Set<number>>(new Set());
	let isExtracting = $state(false);
	let error = $state<string | null>(null);

	// Computed
	let hasSelection = $derived(selectedMessageIndices.size > 0);
	let hasLorebookSelected = $derived(selectedLorebookId !== undefined);
	let canExtract = $derived(hasSelection && hasLorebookSelected && !isExtracting);
	let selectedLorebookName = $derived.by(() => {
		if (!selectedLorebookId) return 'Select a lorebook...';
		const lorebook = lorebooks.find((lb) => lb.id === selectedLorebookId);
		return lorebook?.name || 'Select a lorebook...';
	});

	// Get continuous range from selected indices
	function getMessageRange(): { start: number; end: number } | null {
		if (selectedMessageIndices.size === 0) return null;

		const indices = Array.from(selectedMessageIndices).sort((a, b) => a - b);
		return {
			start: indices[0],
			end: indices[indices.length - 1]
		};
	}

	// Toggle message selection
	function toggleMessage(index: number) {
		const newSet = new Set(selectedMessageIndices);
		if (newSet.has(index)) {
			newSet.delete(index);
		} else {
			newSet.add(index);
		}
		selectedMessageIndices = newSet;
	}

	// Select range of messages
	function selectRange(startIndex: number, endIndex: number) {
		const newSet = new Set<number>();
		for (let i = startIndex; i <= endIndex; i++) {
			newSet.add(i);
		}
		selectedMessageIndices = newSet;
	}

	// Extract lorebook entries
	async function extractEntries() {
		if (!canExtract || !selectedLorebookId) return;

		const range = getMessageRange();
		if (!range) return;

		isExtracting = true;
		error = null;

		const result: Result<{ entries_extracted: number; entries: LorebookEntry[] }, ApiError> =
			await apiClient.extractLorebookEntriesFromChat(selectedLorebookId, {
				chat_session_id: chatSessionId,
				start_message_index: range.start,
				end_message_index: range.end
			});

		if (result.isOk()) {
			const data = result.value;
			onSuccess?.(data.entries);
			onOpenChange(false);
			// Reset state
			selectedMessageIndices = new Set();
			selectedLorebookId = undefined;
		} else {
			error = result.error.message || 'Failed to extract lorebook entries';
		}

		isExtracting = false;
	}

	// Quick select last N messages
	function selectLastN(n: number) {
		if (messages.length === 0) return;
		const startIndex = Math.max(0, messages.length - n);
		selectRange(startIndex, messages.length - 1);
	}
</script>

<Dialog {open} onOpenChange={(o) => onOpenChange(o)}>
	<DialogContent class="flex max-h-[80vh] max-w-2xl flex-col">
		<DialogHeader>
			<DialogTitle>Extract Lorebook Entries from Chat</DialogTitle>
			<DialogDescription>
				Select messages from this chat to extract lorebook entries. The AI will analyze the
				conversation and generate relevant entries.
			</DialogDescription>
		</DialogHeader>

		<div class="flex flex-1 flex-col gap-4 overflow-hidden">
			<!-- Lorebook Selection -->
			<div class="flex flex-col gap-2">
				<Label for="lorebook-select">Target Lorebook</Label>
				<Select
					type="single"
					onValueChange={(v: string | undefined) => {
						if (v) {
							selectedLorebookId = v;
						}
					}}
				>
					<SelectTrigger id="lorebook-select" class="w-full">
						<span class={selectedLorebookId ? '' : 'text-muted-foreground'}>
							{selectedLorebookName}
						</span>
					</SelectTrigger>
					<SelectContent>
						{#each lorebooks as lorebook}
							<SelectItem value={lorebook.id}>{lorebook.name}</SelectItem>
						{/each}
					</SelectContent>
				</Select>
			</div>

			<!-- Quick Selection Buttons -->
			<div class="flex flex-wrap gap-2">
				<Button variant="outline" size="sm" onclick={() => selectLastN(5)}>Last 5</Button>
				<Button variant="outline" size="sm" onclick={() => selectLastN(10)}>Last 10</Button>
				<Button variant="outline" size="sm" onclick={() => selectLastN(20)}>Last 20</Button>
				<Button variant="outline" size="sm" onclick={() => selectRange(0, messages.length - 1)}>
					All Messages
				</Button>
				<Button variant="outline" size="sm" onclick={() => (selectedMessageIndices = new Set())}>
					Clear Selection
				</Button>
			</div>

			<!-- Message Selection List -->
			<div class="flex flex-1 flex-col gap-2 overflow-y-auto rounded-md border p-4">
				<Label class="mb-2">
					Select Messages ({selectedMessageIndices.size} selected)
				</Label>

				{#if messages.length === 0}
					<p class="text-sm text-muted-foreground">No messages available to extract from.</p>
				{:else}
					<div class="space-y-2">
						{#each messages as message, index (index)}
							<div class="flex items-start gap-3 rounded p-2 hover:bg-accent">
								<Checkbox
									id={`message-${index}`}
									checked={selectedMessageIndices.has(index)}
									on:change={() => toggleMessage(index)}
								/>
								<label
									for={`message-${index}`}
									class="flex-1 cursor-pointer text-sm leading-relaxed"
								>
									<span class="text-xs font-medium uppercase text-muted-foreground">
										{message.role}:
									</span>
									<span class="ml-2 line-clamp-2">{message.content}</span>
								</label>
							</div>
						{/each}
					</div>
				{/if}
			</div>

			<!-- Error Display -->
			{#if error}
				<div class="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
					{error}
				</div>
			{/if}
		</div>

		<DialogFooter>
			<Button variant="outline" onclick={() => onOpenChange(false)} disabled={isExtracting}>
				Cancel
			</Button>
			<Button onclick={extractEntries} disabled={!canExtract}>
				{#if isExtracting}
					Extracting...
				{:else}
					Extract Entries
				{/if}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>
