<script lang="ts">
	import {
		Dialog,
		DialogContent,
		DialogHeader,
		DialogTitle,
		DialogDescription
	} from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';

	interface Props {
		open: boolean;
		onClose: () => void;
		onExport: (format: 'scribe_minimal' | 'silly_tavern_full') => void;
	}

	let { open = $bindable(), onClose, onExport }: Props = $props();
	let selectedFormat = $state<'scribe_minimal' | 'silly_tavern_full'>('scribe_minimal');

	function handleExport() {
		onExport(selectedFormat);
		onClose();
	}

	function selectFormat(format: 'scribe_minimal' | 'silly_tavern_full') {
		selectedFormat = format;
	}
</script>

<Dialog bind:open>
	<DialogContent>
		<DialogHeader>
			<DialogTitle>Export Lorebook</DialogTitle>
			<DialogDescription>Choose the export format for your lorebook</DialogDescription>
		</DialogHeader>

		<div class="space-y-3 py-4">
			<button
				class="w-full rounded-lg border p-4 text-left transition-colors {selectedFormat ===
				'scribe_minimal'
					? 'border-primary bg-primary/5'
					: 'border-border hover:bg-accent'}"
				onclick={() => selectFormat('scribe_minimal')}
			>
				<div class="space-y-1">
					<h4 class="text-sm font-medium">Scribe (Minimal RAG Format)</h4>
					<p class="text-sm text-muted-foreground">
						Clean format with only title, keywords, and content. Ideal for RAG-based systems.
					</p>
				</div>
			</button>

			<button
				class="w-full rounded-lg border p-4 text-left transition-colors {selectedFormat ===
				'silly_tavern_full'
					? 'border-primary bg-primary/5'
					: 'border-border hover:bg-accent'}"
				onclick={() => selectFormat('silly_tavern_full')}
			>
				<div class="space-y-1">
					<h4 class="text-sm font-medium">SillyTavern (Full Format)</h4>
					<p class="text-sm text-muted-foreground">
						Complete format with all metadata including insertion order, placement hints, and
						probability settings.
					</p>
				</div>
			</button>
		</div>

		<div class="flex justify-end gap-3">
			<Button variant="outline" onclick={onClose}>Cancel</Button>
			<Button onclick={handleExport}>Export</Button>
		</div>
	</DialogContent>
</Dialog>
