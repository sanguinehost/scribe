<script lang="ts">
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import { Checkbox as CheckboxComponent } from '$lib/components/ui/checkbox';
	import { Label } from '$lib/components/ui/label';
	import { BookOpen, Search, Clock, Sparkles } from 'lucide-svelte';

	// SVELTE 5: Use $bindable() for two-way binding with parent
	let {
		open = $bindable(false),
		onConfirm,
		onOpenChange
	}: {
		open?: boolean;
		onConfirm: (enableChronicle: boolean, rememberChoice: boolean) => void;
		onOpenChange?: (newOpen: boolean) => void;
	} = $props();

	let rememberChoice = $state(false);

	// Handle dialog open state changes from bits-ui Dialog.Root
	function handleDialogOpenChange(newOpen: boolean) {
		open = newOpen; // Sync via $bindable two-way binding
		onOpenChange?.(newOpen);

		if (!newOpen) {
			rememberChoice = false;
		}
	}

	function handleEnable() {
		// Close dialog first via local state update
		handleDialogOpenChange(false);
		// Then trigger callback
		// Use setTimeout to allow UI to update first
		setTimeout(() => {
			onConfirm(true, rememberChoice);
		}, 0);
	}

	function handleSkip() {
		// Close dialog first via local state update
		handleDialogOpenChange(false);
		// Then trigger callback
		setTimeout(() => {
			onConfirm(false, rememberChoice);
		}, 0);
	}
</script>

<Dialog bind:open onOpenChange={handleDialogOpenChange}>
	<DialogContent class="sm:max-w-[500px]">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<BookOpen class="h-5 w-5" />
				Enable Chronicles for this chat?
			</DialogTitle>
			<DialogDescription class="space-y-3 pt-3">
				<p>
					Chronicles track the narrative of your conversation, creating a searchable history of
					events and story developments.
				</p>

				<div class="space-y-2 pt-2">
					<h4 class="text-sm font-medium">Benefits of Chronicles:</h4>
					<ul class="text-muted-foreground space-y-2 text-sm">
						<li class="flex items-start gap-2">
							<BookOpen class="text-primary mt-0.5 h-4 w-4" />
							<span>Automatic story tracking and event extraction</span>
						</li>
						<li class="flex items-start gap-2">
							<Search class="text-primary mt-0.5 h-4 w-4" />
							<span>Smart context search across all your sessions</span>
						</li>
						<li class="flex items-start gap-2">
							<Sparkles class="text-primary mt-0.5 h-4 w-4" />
							<span>Optional AI agent for automatic context enrichment</span>
						</li>
						<li class="flex items-start gap-2">
							<Sparkles class="text-primary mt-0.5 h-4 w-4" />
							<span>Character and world evolution tracking</span>
						</li>
						<li class="flex items-start gap-2">
							<Clock class="text-primary mt-0.5 h-4 w-4" />
							<span>Timeline of significant narrative events</span>
						</li>
					</ul>
				</div>

				<div class="bg-muted/50 rounded-lg p-3 text-sm">
					<p class="mb-1 font-medium">Recommended for:</p>
					<p class="text-muted-foreground">
						Extended roleplays, ongoing stories, world-building sessions, or any conversation you
						want to reference later.
					</p>
				</div>

				<p class="text-muted-foreground text-xs italic">
					You can always enable chronicles later using the re-chronicle feature in chat settings.
				</p>
			</DialogDescription>
		</DialogHeader>

		<div class="flex items-center space-x-2 py-2">
			<CheckboxComponent id="remember-choice" bind:checked={rememberChoice} />
			<Label for="remember-choice" class="cursor-pointer text-sm font-normal">
				Remember my choice for this session
			</Label>
		</div>

		<DialogFooter class="sm:justify-between">
			<ButtonComponent variant="outline" onclick={handleSkip}>Skip for Now</ButtonComponent>
			<ButtonComponent onclick={handleEnable} class="gap-2">
				<BookOpen class="h-4 w-4" />
				Enable Chronicles
			</ButtonComponent>
		</DialogFooter>
	</DialogContent>
</Dialog>
