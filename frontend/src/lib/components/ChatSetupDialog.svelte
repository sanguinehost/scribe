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
	import { BookOpen, Search, Clock, Sparkles, Crown, Swords, ScrollText } from 'lucide-svelte';
	import { Switch } from '$lib/components/ui/switch';

	// SVELTE 5: Use $bindable() for two-way binding with parent
	let {
		open = $bindable(false),
		onConfirm,
		onOpenChange
	}: {
		open?: boolean;
		onConfirm: (options: {
			enableChronicle: boolean;
			enableGameMaster: boolean;
			rememberChoice: boolean;
		}) => void;
		onOpenChange?: (newOpen: boolean) => void;
	} = $props();

	let enableChronicle = $state(true); // Default to true as it's a core feature
	let enableGameMaster = $state(false);
	let rememberChoice = $state(false);

	// Handle dialog open state changes from bits-ui Dialog.Root
	function handleDialogOpenChange(newOpen: boolean) {
		open = newOpen; // Sync via $bindable two-way binding
		onOpenChange?.(newOpen);
		// Reset state when dialog closes
		if (!newOpen) {
			rememberChoice = false;
		}
	}

	function handleStart() {
		// Close dialog directly FIRST
		handleDialogOpenChange(false);
		setTimeout(() => {
			onConfirm({
				enableChronicle,
				enableGameMaster,
				rememberChoice
			});
		}, 0);
	}

	function handleSkip() {
		// Close dialog directly FIRST
		handleDialogOpenChange(false);
		setTimeout(() => {
			onConfirm({
				enableChronicle: false,
				enableGameMaster: false,
				rememberChoice
			});
		}, 0);
	}
</script>

<Dialog bind:open onOpenChange={handleDialogOpenChange}>
	<DialogContent class="sm:max-w-[600px]">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2 text-xl">
				<Sparkles class="h-5 w-5 text-primary" />
				Customize your Chat Experience
			</DialogTitle>
			<DialogDescription>
				Choose the features you want to enable for this session. You can change these later in
				settings.
			</DialogDescription>
		</DialogHeader>

		<div class="grid gap-6 py-4">
			<!-- Chronicles Section -->
			<div
				class="flex items-start space-x-4 rounded-lg border p-4 transition-colors hover:bg-accent/50"
			>
				<div class="mt-1">
					<BookOpen class="h-6 w-6 text-blue-500" />
				</div>
				<div class="flex-1 space-y-1">
					<div class="flex items-center justify-between">
						<Label for="chronicle-toggle" class="cursor-pointer text-base font-medium"
							>Chronicles</Label
						>
						<Switch id="chronicle-toggle" bind:checked={enableChronicle} />
					</div>
					<p class="text-sm text-muted-foreground">
						Tracks the narrative history, creating a searchable timeline of events and story
						developments.
					</p>
					{#if enableChronicle}
						<ul class="mt-2 grid grid-cols-2 gap-1 text-xs text-muted-foreground">
							<li class="flex items-center gap-1">
								<Search class="h-3 w-3" /> Smart context search
							</li>
							<li class="flex items-center gap-1">
								<Clock class="h-3 w-3" /> Timeline tracking
							</li>
						</ul>
					{/if}
				</div>
			</div>

			<!-- Game Master Section -->
			<div
				class="flex items-start space-x-4 rounded-lg border p-4 transition-colors hover:bg-accent/50"
			>
				<div class="mt-1">
					<Crown class="h-6 w-6 text-purple-500" />
				</div>
				<div class="flex-1 space-y-1">
					<div class="flex items-center justify-between">
						<Label for="gm-toggle" class="cursor-pointer text-base font-medium"
							>Game Master Mode</Label
						>
						<Switch id="gm-toggle" bind:checked={enableGameMaster} />
					</div>
					<p class="text-sm text-muted-foreground">
						Adds RPG mechanics including inventory management, quest tracking, and vital statistics.
					</p>
					{#if enableGameMaster}
						<ul class="mt-2 grid grid-cols-2 gap-1 text-xs text-muted-foreground">
							<li class="flex items-center gap-1">
								<ScrollText class="h-3 w-3" /> Quest tracking
							</li>
							<li class="flex items-center gap-1">
								<Swords class="h-3 w-3" /> Inventory system
							</li>
						</ul>
					{/if}
				</div>
			</div>
		</div>

		<div class="flex items-center space-x-2 py-2">
			<CheckboxComponent id="remember-choice" bind:checked={rememberChoice} />
			<Label for="remember-choice" class="cursor-pointer text-sm font-normal text-muted-foreground">
				Remember my choices for future chats
			</Label>
		</div>

		<DialogFooter class="sm:justify-between">
			<ButtonComponent variant="ghost" onclick={handleSkip}>Skip All</ButtonComponent>
			<ButtonComponent onclick={handleStart} class="min-w-[120px] gap-2">
				Start Chat
			</ButtonComponent>
		</DialogFooter>
	</DialogContent>
</Dialog>
