<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Copy, X } from 'lucide-svelte';
	import { apiClient } from '$lib/api';

	let { 
		open = $bindable(false),
		messageId,
		sessionId 
	}: { 
		open: boolean;
		messageId: string;
		sessionId: string;
	} = $props();

	let rawPrompt = $state<string | null>(null);
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let hasFetched = $state(false);

	// Fetch raw prompt when modal opens (only once per open)
	$effect(() => {
		if (open && !hasFetched && !isLoading) {
			fetchRawPrompt();
		}
	});

	async function fetchRawPrompt() {
		if (isLoading || hasFetched) return;
		
		isLoading = true;
		error = null;
		hasFetched = true;
		
		try {
			const result = await apiClient.getMessageById(messageId);
			if (result.isOk()) {
				const message = result.value;
				
				if (message.raw_prompt) {
					rawPrompt = message.raw_prompt;
				} else {
					error = 'Raw prompt not available for this message';
				}
			} else {
				console.error('Failed to fetch message:', result.error);
				if (result.error.statusCode === 404) {
					error = 'Message not found - it may still be processing';
				} else {
					error = `Failed to fetch message: ${result.error.message}`;
				}
			}
		} catch (err) {
			console.error('Error fetching raw prompt:', err);
			error = 'Network error occurred';
		} finally {
			isLoading = false;
		}
	}

	async function copyToClipboard() {
		if (!rawPrompt) return;
		
		try {
			await navigator.clipboard.writeText(rawPrompt);
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	function handleOpenChange(newOpen: boolean) {
		open = newOpen;
		// Reset state when closing
		if (!newOpen) {
			rawPrompt = null;
			error = null;
			isLoading = false;
			hasFetched = false;
		}
	}
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
	<Dialog.Content class="max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
		<Dialog.Header class="flex flex-row items-center justify-between border-b pb-4">
			<div>
				<Dialog.Title class="text-lg font-semibold">Raw Prompt Debug</Dialog.Title>
				<Dialog.Description class="text-sm text-muted-foreground mt-1">
					The complete prompt that was sent to the AI model
				</Dialog.Description>
			</div>
			<div class="flex items-center gap-2">
				{#if rawPrompt}
					<Button
						variant="outline"
						size="sm"
						onclick={copyToClipboard}
						class="gap-2"
					>
						<Copy size={14} />
						Copy
					</Button>
				{/if}
			</div>
		</Dialog.Header>

		<div class="flex-1 overflow-hidden mt-4">
			{#if isLoading}
				<div class="flex items-center justify-center py-12">
					<div class="flex items-center gap-3 text-muted-foreground">
						<div class="h-5 w-5 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
						Loading debug information...
					</div>
				</div>
			{:else if error}
				<div class="flex flex-col items-center justify-center py-12">
					<div class="mb-4 rounded-lg bg-destructive/10 p-4 text-center">
						<div class="mb-2 text-sm font-medium text-destructive">Error</div>
						<p class="text-sm text-muted-foreground">{error}</p>
					</div>
					<Button 
						variant="outline"
						onclick={() => {
							hasFetched = false;
							fetchRawPrompt();
						}}
						disabled={isLoading}
					>
						Retry
					</Button>
				</div>
			{:else if rawPrompt}
				<div class="h-full overflow-auto rounded-lg border bg-muted/20">
					<div class="sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2">
						<div class="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400">
							<div class="h-2 w-2 rounded-full bg-emerald-500"></div>
							Raw Prompt ({rawPrompt.length.toLocaleString()} characters)
						</div>
					</div>
					<pre class="p-4 text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap break-words font-mono">{rawPrompt}</pre>
				</div>
			{:else}
				<div class="flex items-center justify-center py-12">
					<div class="text-muted-foreground">No data loaded</div>
				</div>
			{/if}
		</div>
	</Dialog.Content>
</Dialog.Root>