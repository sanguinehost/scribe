<script lang="ts">
	import type {
		LorebookEntry,
		CreateLorebookEntryPayload,
		UpdateLorebookEntryPayload
	} from '$lib/types';
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
	let isEnabled = $state(entry?.is_enabled ?? true);
	let isConstant = $state(entry?.is_constant ?? false);

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
			is_enabled: isEnabled,
			is_constant: isConstant
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
		isEnabled = entry?.is_enabled ?? true;
		isConstant = entry?.is_constant ?? false;
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
				<p class="text-xs text-muted-foreground">Keywords help with UI search and organization</p>
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
					<Label for="is-enabled" class="cursor-pointer text-sm">Enabled</Label>
				</div>

				<div class="flex items-center space-x-2">
					<input
						type="checkbox"
						id="is-constant"
						bind:checked={isConstant}
						disabled={isLoading}
						class="h-4 w-4 rounded border-gray-300 text-primary focus:ring-2 focus:ring-primary disabled:cursor-not-allowed disabled:opacity-50"
					/>
					<Label for="is-constant" class="cursor-pointer text-sm">Constant</Label>
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
						<div
							class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
						></div>
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
