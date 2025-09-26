<script lang="ts">
	import type { Lorebook, CreateLorebookPayload, UpdateLorebookPayload } from '$lib/types';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea as TextareaComponent } from '$lib/components/ui/textarea';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';

	interface Props {
		lorebook?: Lorebook | null;
		isLoading?: boolean;
		onSubmit?: (_data: CreateLorebookPayload | UpdateLorebookPayload) => void;
		onCancel?: () => void;
	}

	let { lorebook = null, isLoading = false, onSubmit, onCancel }: Props = $props();

	let name = $state(lorebook?.name || '');
	let description = $state(lorebook?.description || '');

	const isEditing = lorebook !== null;
	const title = isEditing ? 'Edit Lorebook' : 'Create New Lorebook';
	const submitLabel = isEditing ? 'Update Lorebook' : 'Create Lorebook';

	function handleSubmit(_event: Event) {
		_event.preventDefault();

		if (!name.trim()) {
			return;
		}

		const payload = {
			name: name.trim(),
			description: description.trim() || undefined
		};

		onSubmit?.(payload);
	}

	function handleCancel() {
		onCancel?.();
	}

	// Reset form when lorebook changes
	$effect(() => {
		name = lorebook?.name || '';
		description = lorebook?.description || '';
	});
</script>

<Card class="w-full max-w-md">
	<CardHeader>
		<CardTitle>{title}</CardTitle>
	</CardHeader>
	<CardContent>
		<form onsubmit={handleSubmit} class="space-y-4">
			<div class="space-y-2">
				<Label for="lorebook-name">Name</Label>
				<Input
					id="lorebook-name"
					bind:value={name}
					placeholder="Enter lorebook name"
					required
					disabled={isLoading}
				/>
			</div>

			<div class="space-y-2">
				<Label for="lorebook-description">Description</Label>
				<TextareaComponent
					id="lorebook-description"
					bind:value={description}
					placeholder="Enter lorebook description (optional)"
					rows={3}
					disabled={isLoading}
				/>
			</div>

			<div class="flex gap-2 pt-4">
				<ButtonComponent type="submit" disabled={isLoading || !name.trim()} class="flex-1">
					{#if isLoading}
						<div
							class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
						></div>
					{/if}
					{submitLabel}
				</ButtonComponent>
				{#if onCancel}
					<ButtonComponent
						type="button"
						variant="outline"
						onclick={handleCancel}
						disabled={isLoading}
					>
						Cancel
					</ButtonComponent>
				{/if}
			</div>
		</form>
	</CardContent>
</Card>
