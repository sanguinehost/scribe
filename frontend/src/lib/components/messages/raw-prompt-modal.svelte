<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Copy } from 'lucide-svelte';
	import { apiClient as _apiClient } from '$lib/api';

	let {
		open = $bindable(false),
		messageId
	}: {
		open: boolean;
		messageId: string;
	} = $props();

	let rawPrompt = $state<string | null>(null);
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let hasFetched = $state(false);
	let retryCount = $state(0);
	let retryTimeout = $state<ReturnType<typeof setTimeout> | null>(null);

	// Fetch raw prompt when modal opens
	$effect(() => {
		if (open && !hasFetched && !isLoading && !rawPrompt) {
			fetchRawPrompt();
		}
	});

	async function fetchRawPrompt() {
		if (isLoading) return;

		isLoading = true;
		error = null;

		try {
			const result = await _apiClient.getMessageById(messageId);
			if (result.isOk()) {
				const message = result.value;

				if (message.raw_prompt) {
					rawPrompt = message.raw_prompt;
					retryCount = 0; // Reset retry count on success
					hasFetched = true;
				} else {
					error = 'Raw prompt not available for this message';
					hasFetched = true;
				}
			} else {
				console.error('Failed to fetch message:', result.error);
				if ('statusCode' in result.error && result.error.statusCode === 404) {
					// Message not found - likely still being saved
					retryCount++;
					if (retryCount <= 5) {
						// Max 5 retries
						const delay = Math.min(1000 * Math.pow(2, retryCount - 1), 8000); // Exponential backoff, max 8s
						error = `Message still processing, retrying in ${Math.ceil(delay / 1000)}s... (${retryCount}/5)`;

						// Clear any existing timeout
						if (retryTimeout) {
							clearTimeout(retryTimeout);
						}

						// Schedule retry
						retryTimeout = setTimeout(() => {
							if (open) {
								// Only retry if modal is still open
								isLoading = true; // Ensure loading state is maintained
								fetchRawPrompt();
							}
						}, delay);
						isLoading = false; // Show error message during wait
						return;
					} else {
						error = 'Message not found after multiple retries - it may have failed to save';
						hasFetched = true;
					}
				} else {
					error = `Failed to fetch message: ${result.error.message}`;
					hasFetched = true;
				}
			}
		} catch (err) {
			console.error('Error fetching raw prompt:', err);
			error = 'Network error occurred';
			hasFetched = true;
		} finally {
			// Only set loading to false if we're not retrying
			if (!retryTimeout) {
				isLoading = false;
			}
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
			retryCount = 0;
			if (retryTimeout) {
				clearTimeout(retryTimeout);
				retryTimeout = null;
			}
		}
	}
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
	<Dialog.Content class="flex max-h-[80vh] max-w-4xl flex-col">
		<Dialog.Header class="flex flex-row items-center justify-between border-b pb-4">
			<div>
				<Dialog.Title class="text-lg font-semibold">Raw Prompt Debug</Dialog.Title>
				<Dialog.Description class="text-muted-foreground mt-1 text-sm">
					The complete prompt that was sent to the AI model
				</Dialog.Description>
			</div>
			<div class="flex items-center gap-2">
				{#if rawPrompt}
					<ButtonComponent variant="outline" size="sm" onclick={copyToClipboard} class="gap-2">
						<Copy size={14} />
						Copy
					</ButtonComponent>
				{/if}
			</div>
		</Dialog.Header>

		<div class="mt-4 min-h-0 flex-1 overflow-y-auto">
			{#if isLoading}
				<div class="flex items-center justify-center py-12">
					<div class="text-muted-foreground flex items-center gap-3">
						<div
							class="h-5 w-5 animate-spin rounded-full border-2 border-current border-t-transparent"
						></div>
						{#if retryCount > 0}
							Loading debug information... (attempt {retryCount + 1})
						{:else}
							Loading debug information...
						{/if}
					</div>
				</div>
			{:else if error}
				<div class="flex flex-col items-center justify-center py-12">
					<div class="bg-destructive/10 mb-4 rounded-lg p-4 text-center">
						<div class="text-destructive mb-2 text-sm font-medium">Error</div>
						<p class="text-muted-foreground text-sm">{error}</p>
					</div>
					<ButtonComponent
						variant="outline"
						onclick={() => {
							hasFetched = false;
							retryCount = 0;
							if (retryTimeout) {
								clearTimeout(retryTimeout);
								retryTimeout = null;
							}
							fetchRawPrompt();
						}}
						disabled={isLoading}
					>
						Retry
					</ButtonComponent>
				</div>
			{:else if rawPrompt}
				<div class="bg-muted/20 rounded-lg border">
					<div class="bg-muted/80 sticky top-0 z-10 border-b px-4 py-2 backdrop-blur-sm">
						<div
							class="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400"
						>
							<div class="h-2 w-2 rounded-full bg-emerald-500"></div>
							Raw Prompt ({rawPrompt.length.toLocaleString()} characters)
						</div>
					</div>
					<pre
						class="text-foreground/90 whitespace-pre-wrap break-words p-4 font-mono text-xs leading-relaxed">{rawPrompt}</pre>
				</div>
			{:else}
				<div class="flex items-center justify-center py-12">
					<div class="text-muted-foreground">No data loaded</div>
				</div>
			{/if}
		</div>
	</Dialog.Content>
</Dialog.Root>
