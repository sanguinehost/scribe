<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Copy, X, Info } from 'lucide-svelte';
	import type { GenerateCharacterFieldResponse } from '$lib/types';

	let { 
		open = $bindable(false),
		generationResponse
	}: { 
		open: boolean;
		generationResponse: GenerateCharacterFieldResponse | null;
	} = $props();

	let copiedSection = $state<string | null>(null);

	async function copyToClipboard(text: string, section: string) {
		if (!text) return;
		
		try {
			await navigator.clipboard.writeText(text);
			copiedSection = section;
			setTimeout(() => copiedSection = null, 2000);
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	function handleOpenChange(newOpen: boolean) {
		open = newOpen;
		if (!newOpen) {
			copiedSection = null;
		}
	}

	// Derived values for easier access
	const debugInfo = $derived(generationResponse?.metadata?.debug_info);
	const hasDebugInfo = $derived(!!debugInfo);
	const lorebookInfo = $derived(debugInfo ? {
		included: debugInfo.lorebook_context_included,
		entriesCount: debugInfo.lorebook_entries_count,
		queryText: debugInfo.query_text_used
	} : null);
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
	<Dialog.Content class="max-w-5xl max-h-[85vh] overflow-hidden flex flex-col">
		<Dialog.Header class="flex flex-row items-center justify-between border-b pb-4">
			<div>
				<Dialog.Title class="text-lg font-semibold">Character Generation Debug</Dialog.Title>
				<Dialog.Description class="text-sm text-muted-foreground mt-1">
					Debug information from character field generation including system prompt and lorebook integration
				</Dialog.Description>
			</div>
		</Dialog.Header>

		<div class="flex-1 overflow-hidden mt-4">
			{#if !hasDebugInfo}
				<div class="flex flex-col items-center justify-center py-12">
					<div class="mb-4 rounded-lg bg-muted/20 p-6 text-center">
						<Info class="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
						<div class="mb-2 text-sm font-medium">No Debug Information</div>
						<p class="text-sm text-muted-foreground">
							Debug information is not available for this generation.
						</p>
					</div>
				</div>
			{:else}
				<div class="space-y-4 h-full overflow-auto">
					<!-- Generation Metadata -->
					<div class="rounded-lg border bg-muted/20">
						<div class="sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-2 text-xs font-medium text-blue-600 dark:text-blue-400">
									<div class="h-2 w-2 rounded-full bg-blue-500"></div>
									Generation Summary
								</div>
							</div>
						</div>
						<div class="p-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
							<div>
								<div class="font-medium text-muted-foreground">Model</div>
								<div class="mt-1">{generationResponse?.metadata?.model_used || 'Unknown'}</div>
							</div>
							<div>
								<div class="font-medium text-muted-foreground">Tokens Used</div>
								<div class="mt-1">{generationResponse?.metadata?.tokens_used?.toLocaleString() || 'Unknown'}</div>
							</div>
							<div>
								<div class="font-medium text-muted-foreground">Generation Time</div>
								<div class="mt-1">{generationResponse?.metadata?.generation_time_ms || 0}ms</div>
							</div>
							<div>
								<div class="font-medium text-muted-foreground">Style Used</div>
								<div class="mt-1">{generationResponse?.style_used || 'Unknown'}</div>
							</div>
						</div>
					</div>

					<!-- Lorebook Integration Status -->
					{#if lorebookInfo}
						<div class="rounded-lg border bg-muted/20">
							<div class="sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2 text-xs font-medium {lorebookInfo.included ? 'text-green-600 dark:text-green-400' : 'text-orange-600 dark:text-orange-400'}">
										<div class="h-2 w-2 rounded-full {lorebookInfo.included ? 'bg-green-500' : 'bg-orange-500'}"></div>
										Lorebook Integration
									</div>
								</div>
							</div>
							<div class="p-4 space-y-3 text-sm">
								<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
									<div>
										<div class="font-medium text-muted-foreground">Context Included</div>
										<div class="mt-1 flex items-center gap-2">
											<span class="{lorebookInfo.included ? 'text-green-600 dark:text-green-400' : 'text-orange-600 dark:text-orange-400'}">
												{lorebookInfo.included ? 'Yes' : 'No'}
											</span>
										</div>
									</div>
									<div>
										<div class="font-medium text-muted-foreground">Entries Found</div>
										<div class="mt-1">
											{lorebookInfo.entriesCount !== null ? lorebookInfo.entriesCount : 'Unknown'}
										</div>
									</div>
									<div>
										<div class="font-medium text-muted-foreground">Query Used</div>
										<div class="mt-1 truncate">
											{lorebookInfo.queryText || 'None'}
										</div>
									</div>
								</div>
								{#if lorebookInfo.queryText}
									<div class="border-t pt-3">
										<div class="flex items-center justify-between mb-2">
											<div class="font-medium text-muted-foreground">Full Query Text</div>
											<Button
												variant="outline"
												size="sm"
												onclick={() => copyToClipboard(lorebookInfo.queryText!, 'query')}
												class="gap-2 h-7 text-xs"
											>
												<Copy size={12} />
												{copiedSection === 'query' ? 'Copied!' : 'Copy'}
											</Button>
										</div>
										<div class="bg-muted p-3 rounded text-xs font-mono">
											{lorebookInfo.queryText}
										</div>
									</div>
								{/if}
							</div>
						</div>
					{/if}

					<!-- System Prompt -->
					{#if debugInfo?.system_prompt}
						<div class="rounded-lg border bg-muted/20">
							<div class="sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2 text-xs font-medium text-purple-600 dark:text-purple-400">
										<div class="h-2 w-2 rounded-full bg-purple-500"></div>
										System Prompt ({debugInfo.system_prompt.length.toLocaleString()} characters)
									</div>
									<Button
										variant="outline"
										size="sm"
										onclick={() => copyToClipboard(debugInfo.system_prompt, 'system')}
										class="gap-2 h-7 text-xs"
									>
										<Copy size={12} />
										{copiedSection === 'system' ? 'Copied!' : 'Copy'}
									</Button>
								</div>
							</div>
							<pre class="p-4 text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap break-words font-mono max-h-64 overflow-auto">{debugInfo.system_prompt}</pre>
						</div>
					{/if}

					<!-- User Message -->
					{#if debugInfo?.user_message}
						<div class="rounded-lg border bg-muted/20">
							<div class="sticky top-0 bg-muted/80 backdrop-blur-sm border-b px-4 py-2">
								<div class="flex items-center justify-between">
									<div class="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400">
										<div class="h-2 w-2 rounded-full bg-emerald-500"></div>
										User Message ({debugInfo.user_message.length.toLocaleString()} characters)
									</div>
									<Button
										variant="outline"
										size="sm"
										onclick={() => copyToClipboard(debugInfo.user_message, 'user')}
										class="gap-2 h-7 text-xs"
									>
										<Copy size={12} />
										{copiedSection === 'user' ? 'Copied!' : 'Copy'}
									</Button>
								</div>
							</div>
							<pre class="p-4 text-xs leading-relaxed text-foreground/90 whitespace-pre-wrap break-words font-mono max-h-64 overflow-auto">{debugInfo.user_message}</pre>
						</div>
					{/if}
				</div>
			{/if}
		</div>
	</Dialog.Content>
</Dialog.Root>