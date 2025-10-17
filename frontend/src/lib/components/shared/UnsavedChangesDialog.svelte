<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import Button from '$lib/components/ui/button/button.svelte';
	import { AlertTriangle } from 'lucide-svelte';

	interface Props {
		open: boolean;
		characterName?: string;
		isSaving?: boolean;
		onSave: () => void | Promise<void>;
		onDiscard: () => void;
		onCancel: () => void;
	}

	let { open, characterName, isSaving = false, onSave, onDiscard, onCancel }: Props = $props();
</script>

<Dialog.Root {open} onOpenChange={(isOpen) => !isOpen && onCancel()}>
	<Dialog.Content class="sm:max-w-[425px]">
		<Dialog.Header>
			<div class="flex items-start gap-4">
				<div
					class="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-950"
				>
					<AlertTriangle class="h-6 w-6 text-amber-600 dark:text-amber-500" />
				</div>
				<div class="flex-1 space-y-2">
					<Dialog.Title>Unsaved Changes</Dialog.Title>
					<Dialog.Description class="text-sm text-muted-foreground">
						{#if characterName}
							Changes to <span class="font-semibold text-foreground">"{characterName}"</span> will be
							lost if you close without saving.
						{:else}
							You have unsaved changes that will be lost if you close without saving.
						{/if}
					</Dialog.Description>
				</div>
			</div>
		</Dialog.Header>

		<Dialog.Footer class="flex-col gap-2 sm:flex-row sm:justify-end">
			<Button variant="outline" onclick={onCancel} disabled={isSaving} class="w-full sm:w-auto">
				Cancel
			</Button>
			<Button
				variant="destructive"
				onclick={onDiscard}
				disabled={isSaving}
				class="w-full sm:w-auto"
			>
				Discard Changes
			</Button>
			<Button onclick={onSave} disabled={isSaving} class="w-full sm:w-auto">
				{#if isSaving}
					Saving...
				{:else}
					Save Changes
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
