<script lang="ts">
	/**
	 * Generation Debug Modal
	 *
	 * Shows detailed information about generation requests for transparency.
	 * Implements OWASP LLM07 (System Prompt Disclosure) - intentional transparency.
	 */

	import { Dialog, DialogContent, DialogHeader, DialogTitle } from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Label } from '$lib/components/ui/label';
	import { Tabs, TabsContent, TabsList, TabsTrigger } from '$lib/components/ui/tabs';
	import { Copy, Check, Eye } from 'lucide-svelte';
	import type { GenerationMetadata } from '$lib/types/ai';

	interface Props {
		/** Dialog open state */
		open: boolean;
		/** Generation metadata */
		metadata: GenerationMetadata | null;
		/** Callback to close dialog */
		onOpenChange?: (open: boolean) => void;
	}

	let { open = $bindable(false), metadata, onOpenChange }: Props = $props();

	let copiedSystem = $state(false);
	let copiedUser = $state(false);

	// Copy to clipboard
	async function copyToClipboard(text: string, type: 'system' | 'user') {
		try {
			await navigator.clipboard.writeText(text);
			if (type === 'system') {
				copiedSystem = true;
				setTimeout(() => (copiedSystem = false), 2000);
			} else {
				copiedUser = true;
				setTimeout(() => (copiedUser = false), 2000);
			}
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	// Format cost in dollars
	function formatCost(cost: number): string {
		if (cost === 0) return 'Free';
		if (cost < 0.01) return `$${cost.toFixed(4)}`;
		return `$${cost.toFixed(2)}`;
	}
</script>

<Dialog bind:open {onOpenChange}>
	<DialogContent class="max-h-[90vh] max-w-4xl overflow-y-auto">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<Eye class="h-5 w-5" />
				Generation Details
			</DialogTitle>
		</DialogHeader>

		{#if metadata}
			<div class="space-y-4">
				<!-- Metadata Summary -->
				<div class="grid grid-cols-2 gap-4 rounded-md bg-muted p-4">
					<div>
						<div class="text-sm font-semibold">Model</div>
						<div class="text-sm text-muted-foreground">{metadata.model}</div>
					</div>
					<div>
						<div class="text-sm font-semibold">Tokens Used</div>
						<div class="text-sm text-muted-foreground">{metadata.tokensUsed.toLocaleString()}</div>
					</div>
					<div>
						<div class="text-sm font-semibold">Cost</div>
						<div class="text-sm text-muted-foreground">{formatCost(metadata.cost)}</div>
					</div>
					<div>
						<div class="text-sm font-semibold">Generation Time</div>
						<div class="text-sm text-muted-foreground">
							{(metadata.generationTimeMs / 1000).toFixed(2)}s
						</div>
					</div>
					{#if metadata.lorebookContextIncluded !== undefined}
						<div>
							<div class="text-sm font-semibold">Lorebook Context</div>
							<div class="text-sm text-muted-foreground">
								{metadata.lorebookContextIncluded ? 'Included' : 'Not included'}
							</div>
						</div>
						{#if metadata.lorebookEntriesCount !== undefined && metadata.lorebookEntriesCount > 0}
							<div>
								<div class="text-sm font-semibold">Lorebook Entries</div>
								<div class="text-sm text-muted-foreground">
									{metadata.lorebookEntriesCount}
									{metadata.lorebookEntriesCount === 1 ? 'entry' : 'entries'}
								</div>
							</div>
						{/if}
					{/if}
					{#if metadata.finishReason}
						<div class="col-span-2">
							<div class="text-sm font-semibold">Finish Reason</div>
							<div class="text-sm text-muted-foreground">{metadata.finishReason}</div>
						</div>
					{/if}
					{#if metadata.queryTextUsed}
						<div class="col-span-2">
							<div class="text-sm font-semibold">Lorebook Query</div>
							<div class="font-mono text-sm text-muted-foreground">{metadata.queryTextUsed}</div>
						</div>
					{/if}
				</div>

				<!-- Prompts Tabs -->
				{#if metadata.systemPrompt || metadata.userPrompt}
					<Tabs value="system" class="w-full">
						<TabsList class="w-full">
							{#if metadata.systemPrompt}
								<TabsTrigger value="system" class="flex-1">System Prompt</TabsTrigger>
							{/if}
							{#if metadata.userPrompt}
								<TabsTrigger value="user" class="flex-1">User Prompt</TabsTrigger>
							{/if}
						</TabsList>

						{#if metadata.systemPrompt}
							<TabsContent value="system" class="space-y-2">
								<div class="flex items-center justify-between">
									<Label>System Prompt (sent to AI)</Label>
									<Button
										size="sm"
										variant="ghost"
										onclick={() => copyToClipboard(metadata.systemPrompt!, 'system')}
									>
										{#if copiedSystem}
											<Check class="mr-1 h-4 w-4" />
											Copied
										{:else}
											<Copy class="mr-1 h-4 w-4" />
											Copy
										{/if}
									</Button>
								</div>
								<div
									class="max-h-96 overflow-y-auto whitespace-pre-wrap rounded-md border bg-background p-4 font-mono text-sm"
								>
									{metadata.systemPrompt}
								</div>
							</TabsContent>
						{/if}

						{#if metadata.userPrompt}
							<TabsContent value="user" class="space-y-2">
								<div class="flex items-center justify-between">
									<Label>User Prompt (sent to AI)</Label>
									<Button
										size="sm"
										variant="ghost"
										onclick={() => copyToClipboard(metadata.userPrompt!, 'user')}
									>
										{#if copiedUser}
											<Check class="mr-1 h-4 w-4" />
											Copied
										{:else}
											<Copy class="mr-1 h-4 w-4" />
											Copy
										{/if}
									</Button>
								</div>
								<div
									class="max-h-96 overflow-y-auto whitespace-pre-wrap rounded-md border bg-background p-4 font-mono text-sm"
								>
									{metadata.userPrompt}
								</div>
							</TabsContent>
						{/if}
					</Tabs>
				{:else}
					<div class="py-8 text-center text-sm text-muted-foreground">
						No prompt data available. Enable debug mode in settings to capture prompts.
					</div>
				{/if}

				<!-- Info -->
				<div class="text-xs text-muted-foreground">
					This information is provided for transparency. It shows exactly what was sent to the AI
					model.
				</div>
			</div>
		{:else}
			<div class="py-8 text-center text-sm text-muted-foreground">No generation data available</div>
		{/if}
	</DialogContent>
</Dialog>
