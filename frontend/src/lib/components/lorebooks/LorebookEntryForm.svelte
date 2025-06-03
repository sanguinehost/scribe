<script lang="ts">
	import type { LorebookEntry, CreateLorebookEntryPayload, UpdateLorebookEntryPayload } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';

	interface Props {
		entry?: LorebookEntry | null;
		isLoading?: boolean;
		onSubmit?: (data: CreateLorebookEntryPayload | UpdateLorebookEntryPayload) => void;
		onCancel?: () => void;
	}

	let { entry = null, isLoading = false, onSubmit, onCancel }: Props = $props();

	let entryTitle = $state(entry?.entry_title || '');
	let keysText = $state(entry?.keys_text || '');
	let content = $state(entry?.content || '');
	let comment = $state(entry?.comment || '');
	let isEnabled = $state(entry?.is_enabled ?? true);
	let isConstant = $state(entry?.is_constant ?? false);
	let insertionOrder = $state(entry?.insertion_order ?? 100);
	let placementHint = $state(entry?.placement_hint || 'after_prompt');

	const isEditing = entry !== null;
	const title = isEditing ? 'Edit Entry' : 'Create New Entry';
	const submitLabel = isEditing ? 'Update Entry' : 'Create Entry';

	function handleSubmit(event: Event) {
		event.preventDefault();
		
		if (!entryTitle.trim() || !content.trim()) {
			return;
		}

		const payload = {
			entry_title: entryTitle.trim(),
			keys_text: keysText.trim() || undefined,
			content: content.trim(),
			comment: comment.trim() || undefined,
			is_enabled: isEnabled,
			is_constant: isConstant,
			insertion_order: insertionOrder,
			placement_hint: placementHint
		};

		onSubmit?.(payload);
	}

	function handleCancel() {
		onCancel?.();
	}

	// Reset form when entry changes
	$effect(() => {
		entryTitle = entry?.entry_title || '';
		keysText = entry?.keys_text || '';
		content = entry?.content || '';
		comment = entry?.comment || '';
		isEnabled = entry?.is_enabled ?? true;
		isConstant = entry?.is_constant ?? false;
		insertionOrder = entry?.insertion_order ?? 100;
		placementHint = entry?.placement_hint || 'after_prompt';
	});
</script>

<Card class="w-full max-w-2xl">
	<CardHeader>
		<CardTitle>{title}</CardTitle>
	</CardHeader>
	<CardContent>
		<form onsubmit={handleSubmit} class="space-y-4">
			<!-- Entry Title -->
			<div class="space-y-2">
				<Label for="entry-title">Entry Title</Label>
				<Input
					id="entry-title"
					bind:value={entryTitle}
					placeholder="Enter entry title"
					required
					disabled={isLoading}
				/>
			</div>

			<!-- Keywords -->
			<div class="space-y-2">
				<Label for="entry-keys">Keywords</Label>
				<Input
					id="entry-keys"
					bind:value={keysText}
					placeholder="Enter keywords separated by commas (e.g., dragon, fire, magic)"
					disabled={isLoading}
				/>
				<p class="text-xs text-muted-foreground">
					Keywords that will trigger this entry to be included in the context
				</p>
			</div>

			<!-- Content -->
			<div class="space-y-2">
				<Label for="entry-content">Content</Label>
				<Textarea
					id="entry-content"
					bind:value={content}
					placeholder="Enter the lorebook entry content"
					rows={8}
					required
					disabled={isLoading}
				/>
			</div>

			<!-- Comment -->
			<div class="space-y-2">
				<Label for="entry-comment">Comment</Label>
				<Textarea
					id="entry-comment"
					bind:value={comment}
					placeholder="Optional comment or notes about this entry"
					rows={2}
					disabled={isLoading}
				/>
			</div>

			<!-- Settings Row -->
			<div class="grid grid-cols-2 gap-4">
				<!-- Insertion Order -->
				<div class="space-y-2">
					<Label for="insertion-order">Insertion Order</Label>
					<Input
						id="insertion-order"
						type="number"
						bind:value={insertionOrder}
						min="0"
						max="1000"
						step="10"
						disabled={isLoading}
					/>
					<p class="text-xs text-muted-foreground">
						Lower numbers appear first in context
					</p>
				</div>

				<!-- Placement -->
				<div class="space-y-2">
					<Label for="placement-hint">Placement</Label>
					<select
						id="placement-hint"
						bind:value={placementHint}
						disabled={isLoading}
						class="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
					>
						<option value="before_prompt">Before Prompt</option>
						<option value="after_prompt">After Prompt</option>
					</select>
				</div>
			</div>

			<!-- Checkboxes -->
			<div class="flex gap-6">
				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="is-enabled" 
						bind:checked={isEnabled} 
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="is-enabled" class="text-sm cursor-pointer">Enabled</Label>
				</div>

				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="is-constant" 
						bind:checked={isConstant} 
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="is-constant" class="text-sm cursor-pointer">Constant</Label>
					<span class="text-xs text-muted-foreground">(always included)</span>
				</div>
			</div>

			<!-- Submit buttons -->
			<div class="flex gap-2 pt-4">
				<Button 
					type="submit" 
					disabled={isLoading || !entryTitle.trim() || !content.trim()} 
					class="flex-1"
				>
					{#if isLoading}
						<div class="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent mr-2"></div>
					{/if}
					{submitLabel}
				</Button>
				{#if onCancel}
					<Button type="button" variant="outline" onclick={handleCancel} disabled={isLoading}>
						Cancel
					</Button>
				{/if}
			</div>
		</form>
	</CardContent>
</Card>