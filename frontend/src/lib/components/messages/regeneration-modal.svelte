<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import * as RadioGroup from '$lib/components/ui/radio-group';
	import { RadioGroupItem } from '$lib/components/ui/radio-group';
	import { Label } from '$lib/components/ui/label';
	import { Textarea as TextareaComponent } from '$lib/components/ui/textarea';
	import { Zap, Brain, X } from 'lucide-svelte';

	export type AnalysisMode = 'existing' | 'refresh' | 'skip';

	let {
		open = $bindable(false),
		onConfirm,
		onCancel
	}: {
		open: boolean;
		onConfirm: (mode: AnalysisMode, guidance?: string) => void;
		onCancel?: () => void;
	} = $props();

	let selectedMode = $state<AnalysisMode>('existing');
	let guidance = $state('');

	function handleConfirm() {
		// Pass guidance text if provided, otherwise undefined
		const guidanceText = guidance.trim() || undefined;
		onConfirm(selectedMode, guidanceText);
		open = false;
		// Reset to default for next time
		selectedMode = 'existing';
		guidance = '';
	}

	function handleCancel() {
		onCancel?.();
		open = false;
		// Reset to default for next time
		selectedMode = 'existing';
		guidance = '';
	}

	function handleOpenChange(newOpen: boolean) {
		open = newOpen;
		if (!newOpen) {
			// Reset when closing
			selectedMode = 'existing';
			guidance = '';
		}
	}
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
	<Dialog.Content class="sm:max-w-[500px]">
		<Dialog.Header>
			<Dialog.Title>Regenerate Response</Dialog.Title>
			<Dialog.Description>
				Choose how to handle context analysis for the new response
			</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-4 py-4">
			<RadioGroup.Root bind:value={selectedMode} class="gap-4">
				<!-- Quick regeneration option -->
				<div
					class="flex items-start space-x-3 rounded-lg border p-4 transition-colors hover:bg-accent/50"
				>
					<RadioGroupItem value="existing" id="existing" class="mt-1" />
					<Label for="existing" class="flex-1 cursor-pointer">
						<div class="flex items-center gap-2 font-medium">
							<Zap class="h-4 w-4 text-yellow-500" />
							Quick regeneration
						</div>
						<p class="mt-1 text-sm text-muted-foreground">
							Generate new response using existing context analysis
						</p>
						<p class="mt-1 text-xs text-muted-foreground/70">Fastest option (~2-3s)</p>
					</Label>
				</div>

				<!-- Fresh analysis option -->
				<div
					class="flex items-start space-x-3 rounded-lg border p-4 transition-colors hover:bg-accent/50"
				>
					<RadioGroupItem value="refresh" id="refresh" class="mt-1" />
					<Label for="refresh" class="flex-1 cursor-pointer">
						<div class="flex items-center gap-2 font-medium">
							<Brain class="h-4 w-4 text-blue-500" />
							With fresh context analysis
						</div>
						<p class="mt-1 text-sm text-muted-foreground">
							Re-analyze context before generating response
						</p>
						<p class="mt-1 text-xs text-muted-foreground/70">More thorough but slower (~5-7s)</p>
					</Label>
				</div>

				<!-- Skip analysis option -->
				<div
					class="flex items-start space-x-3 rounded-lg border p-4 transition-colors hover:bg-accent/50"
				>
					<RadioGroupItem value="skip" id="skip" class="mt-1" />
					<Label for="skip" class="flex-1 cursor-pointer">
						<div class="flex items-center gap-2 font-medium">
							<X class="h-4 w-4 text-gray-500" />
							Skip context analysis
						</div>
						<p class="mt-1 text-sm text-muted-foreground">
							Generate without any context enrichment
						</p>
						<p class="mt-1 text-xs text-muted-foreground/70">
							Basic response without lorebook/chronicle context (~2s)
						</p>
					</Label>
				</div>
			</RadioGroup.Root>

			<!-- Optional Guidance Section -->
			<div class="space-y-2 border-t pt-4">
				<Label for="guidance" class="text-sm font-medium">Add guidance (optional)</Label>
				<TextareaComponent
					id="guidance"
					bind:value={guidance}
					placeholder="e.g., 'Focus more on the emotional aspects' or 'Be more concise'"
					class="min-h-[60px] resize-none text-sm"
				/>
				<p class="text-xs text-muted-foreground">
					Provide optional instructions to guide how the AI should regenerate the response.
				</p>
			</div>
		</div>

		<Dialog.Footer>
			<ButtonComponent variant="outline" onclick={handleCancel}>Cancel</ButtonComponent>
			<ButtonComponent onclick={handleConfirm}>Regenerate</ButtonComponent>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
