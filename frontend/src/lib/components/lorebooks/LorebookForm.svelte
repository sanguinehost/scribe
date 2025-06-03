<script lang="ts">
	import type { Lorebook, CreateLorebookPayload, UpdateLorebookPayload } from '$lib/types';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';

	interface Props {
		lorebook?: Lorebook | null;
		isLoading?: boolean;
		onSubmit?: (data: CreateLorebookPayload | UpdateLorebookPayload) => void;
		onCancel?: () => void;
	}

	let { lorebook = null, isLoading = false, onSubmit, onCancel }: Props = $props();

	let name = $state(lorebook?.name || '');
	let description = $state(lorebook?.description || '');

	const isEditing = lorebook !== null;
	const title = isEditing ? 'Edit Lorebook' : 'Create New Lorebook';
	const submitLabel = isEditing ? 'Update Lorebook' : 'Create Lorebook';

	function handleSubmit(event: Event) {
		event.preventDefault();
		
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
				<Textarea
					id="lorebook-description"
					bind:value={description}
					placeholder="Enter lorebook description (optional)"
					rows={3}
					disabled={isLoading}
				/>
			</div>

			<div class="flex gap-2 pt-4">
				<Button type="submit" disabled={isLoading || !name.trim()} class="flex-1">
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