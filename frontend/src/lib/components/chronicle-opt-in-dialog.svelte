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
	import { Checkbox } from '$lib/components/ui/checkbox';
	import { Label } from '$lib/components/ui/label';
	import { BookOpen, Search, Clock, Sparkles } from 'lucide-svelte';

	export let open = false;
	export let onConfirm: (enableChronicle: boolean, rememberChoice: boolean) => void;
	
	let rememberChoice = false;

	function handleEnable() {
		onConfirm(true, rememberChoice);
		open = false;
	}

	function handleSkip() {
		onConfirm(false, rememberChoice);
		open = false;
	}
</script>

<Dialog bind:open>
	<DialogContent class="sm:max-w-[500px]">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<BookOpen class="h-5 w-5" />
				Enable Chronicles for this chat?
			</DialogTitle>
			<DialogDescription class="pt-3 space-y-3">
				<p>
					Chronicles track the narrative of your conversation, creating a searchable history of events and story developments.
				</p>
				
				<div class="space-y-2 pt-2">
					<h4 class="font-medium text-sm">Benefits of Chronicles:</h4>
					<ul class="space-y-2 text-sm text-muted-foreground">
						<li class="flex items-start gap-2">
							<BookOpen class="h-4 w-4 mt-0.5 text-primary" />
							<span>Automatic story tracking and event extraction</span>
						</li>
						<li class="flex items-start gap-2">
							<Search class="h-4 w-4 mt-0.5 text-primary" />
							<span>Smart context search across all your sessions</span>
						</li>
						<li class="flex items-start gap-2">
							<Sparkles class="h-4 w-4 mt-0.5 text-primary" />
							<span>Optional AI agent for automatic context enrichment</span>
						</li>
						<li class="flex items-start gap-2">
							<Sparkles class="h-4 w-4 mt-0.5 text-primary" />
							<span>Character and world evolution tracking</span>
						</li>
						<li class="flex items-start gap-2">
							<Clock class="h-4 w-4 mt-0.5 text-primary" />
							<span>Timeline of significant narrative events</span>
						</li>
					</ul>
				</div>

				<div class="bg-muted/50 rounded-lg p-3 text-sm">
					<p class="font-medium mb-1">Recommended for:</p>
					<p class="text-muted-foreground">
						Extended roleplays, ongoing stories, world-building sessions, or any conversation you want to reference later.
					</p>
				</div>

				<p class="text-xs text-muted-foreground italic">
					You can always enable chronicles later using the re-chronicle feature in chat settings.
				</p>
			</DialogDescription>
		</DialogHeader>

		<div class="flex items-center space-x-2 py-2">
			<Checkbox 
				id="remember-choice" 
				bind:checked={rememberChoice}
			/>
			<Label 
				for="remember-choice" 
				class="text-sm font-normal cursor-pointer"
			>
				Remember my choice for this session
			</Label>
		</div>

		<DialogFooter class="sm:justify-between">
			<Button 
				variant="outline" 
				onclick={handleSkip}
			>
				Skip for Now
			</Button>
			<Button 
				onclick={handleEnable}
				class="gap-2"
			>
				<BookOpen class="h-4 w-4" />
				Enable Chronicles
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>