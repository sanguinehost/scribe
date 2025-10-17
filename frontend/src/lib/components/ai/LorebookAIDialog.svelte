<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { characterStore } from '$lib/stores/character.svelte';
	import { aiSettings } from '$lib/stores/ai-settings.svelte';
	import { createProvider } from '$lib/utils/ai/providers';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Alert from '$lib/components/ui/alert';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import WorkflowSummary from '$lib/components/ai/WorkflowSummary.svelte';
	import LorebookPreviewDialog from '$lib/components/ai/LorebookPreviewDialog.svelte';
	import { AlertCircle, Loader2, Sparkles, Check, X } from 'lucide-svelte';
	import type { LorebookEntry } from '$lib/types/character';
	import { toast } from 'svelte-sonner';

	import { LorebookAgentFactory } from '$lib/utils/agentic';
	import type { WorkflowProgress, WorkflowResult } from '$lib/utils/agentic';
	import {
		generateSingleEntryGoal,
		generateSingleEntryContext,
		batchGenerateEntriesGoal,
		batchGenerateEntriesContext,
		enhanceLorebookGoal,
		enhanceLorebookContext,
		getLorebookAgentConfig
	} from '$lib/utils/agentic';

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	const dispatch = createEventDispatcher<{ close: void }>();

	// Workflow state
	let activeTab = $state<string>('single');
	let isExecuting = $state(false);
	let progress = $state<WorkflowProgress | null>(null);
	let result = $state<WorkflowResult | null>(null);
	let error = $state<string | null>(null);

	// Preview state
	let showPreview = $state(false);
	let previewEntries = $state<LorebookEntry[]>([]);

	// Single entry inputs
	let singleTopic = $state('');

	// Batch generate inputs
	let batchCount = $state(5);
	let batchTheme = $state('');

	// Enhance lorebook inputs
	let enhanceMaxEntries = $state(10);

	/**
	 * Execute a workflow
	 */
	async function executeWorkflow(goal: string, context: Record<string, unknown>) {
		const apiKey = aiSettings.getApiKey();

		if (!apiKey || !aiSettings.provider) {
			error = 'Please configure your AI settings first';
			console.error('[LorebookAIDialog] API key or provider not configured');
			return;
		}

		isExecuting = true;
		error = null;
		result = null;
		progress = null;

		console.log('[LorebookAIDialog] Starting workflow execution');
		console.log('[LorebookAIDialog] Goal:', goal);
		console.log('[LorebookAIDialog] Context:', context);

		try {
			// Create AI provider
			const provider = createProvider(aiSettings.provider, apiKey);
			console.log('[LorebookAIDialog] Provider created:', aiSettings.provider);

			// Create agent
			const agent = LorebookAgentFactory.createLorebookAgent(
				provider,
				getLorebookAgentConfig()
			) as {
				executeWorkflowMultiStage: (
					goal: string,
					context: Record<string, unknown>,
					onProgress: (p: WorkflowProgress) => void
				) => Promise<WorkflowResult>;
			};
			console.log('[LorebookAIDialog] Agent created');

			// Execute workflow with progress callback (using multi-stage adaptive planning)
			const workflowResult = await agent.executeWorkflowMultiStage(
				goal,
				context,
				(p: WorkflowProgress) => {
					progress = p;
				}
			);

			result = workflowResult;
			console.log('[LorebookAIDialog] Workflow result:', workflowResult);

			if (!workflowResult.success) {
				const errorMsg = workflowResult.error || 'Workflow failed';
				error = errorMsg;
				console.error('[LorebookAIDialog] Workflow failed:', errorMsg);
				console.error('[LorebookAIDialog] Tool executions:', workflowResult.toolExecutions);
			} else {
				console.log('[LorebookAIDialog] Workflow completed successfully');

				// Check for created lorebook entries and show preview
				const batchCreateExecutions = workflowResult.toolExecutions.filter(
					(exec) => exec.toolName === 'batch_create_lorebook_entries' && exec.success
				);

				if (batchCreateExecutions.length > 0) {
					// Extract all created entries
					const allEntries: LorebookEntry[] = [];
					for (const exec of batchCreateExecutions) {
						const result = exec.result as { entries?: LorebookEntry[] } | undefined;
						if (result?.entries && Array.isArray(result.entries)) {
							allEntries.push(...result.entries);
						}
					}

					if (allEntries.length > 0) {
						console.log('[LorebookAIDialog] Found', allEntries.length, 'entries, showing preview');

						// Entries are NOT added to character yet - they're just validated and returned by the tool
						// User will review them in preview, then we add only the approved ones

						// Close lorebook dialog and show preview (mutually exclusive)
						previewEntries = allEntries;
						open = false; // Close lorebook dialog first

						// Open preview after dialog close animation
						setTimeout(() => {
							showPreview = true;
						}, 150);
					}
				}
			}
		} catch (e) {
			const errorMsg = e instanceof Error ? e.message : 'Unknown error occurred';
			error = errorMsg;
			console.error('[LorebookAIDialog] Exception during workflow:', errorMsg);
			console.error('[LorebookAIDialog] Stack:', e instanceof Error ? e.stack : 'N/A');
		} finally {
			isExecuting = false;
		}
	}

	/**
	 * Generate single entry
	 */
	async function handleGenerateSingle() {
		if (!singleTopic.trim()) {
			error = 'Please enter a topic';
			return;
		}

		const goal = generateSingleEntryGoal(singleTopic);
		const context = generateSingleEntryContext(singleTopic);

		await executeWorkflow(goal, context);
	}

	/**
	 * Batch generate entries
	 */
	async function handleBatchGenerate() {
		if (batchCount < 1 || batchCount > 20) {
			error = 'Count must be between 1 and 20';
			return;
		}

		const goal = batchGenerateEntriesGoal(batchCount, batchTheme || undefined);
		const context = batchGenerateEntriesContext(batchCount, batchTheme || undefined);

		await executeWorkflow(goal, context);
	}

	/**
	 * Enhance lorebook
	 */
	async function handleEnhanceLorebook() {
		if (enhanceMaxEntries < 1 || enhanceMaxEntries > 20) {
			error = 'Max entries must be between 1 and 20';
			return;
		}

		const goal = enhanceLorebookGoal(enhanceMaxEntries);
		const context = enhanceLorebookContext(enhanceMaxEntries);

		await executeWorkflow(goal, context);
	}

	/**
	 * Reset state
	 */
	function handleClose() {
		open = false;
		dispatch('close');
		// Reset after dialog closes
		setTimeout(() => {
			isExecuting = false;
			progress = null;
			result = null;
			error = null;
			singleTopic = '';
			batchTheme = '';
		}, 300);
	}

	/**
	 * Cancel workflow
	 */
	function handleCancel() {
		// TODO: Implement workflow cancellation
		isExecuting = false;
		error = 'Workflow cancelled';
	}

	/**
	 * Handle preview approval - create the approved entries
	 */
	function handlePreviewApprove(approvedEntries: LorebookEntry[]) {
		console.log('[LorebookAIDialog] User approved', approvedEntries.length, 'entries');

		// Create the approved entries
		for (const entry of approvedEntries) {
			characterStore.addLorebookEntry(entry);
		}

		toast.success('Lorebook entries added', {
			description: `Successfully added ${approvedEntries.length} ${approvedEntries.length === 1 ? 'entry' : 'entries'} to your lorebook`
		});

		showPreview = false;
		previewEntries = [];
	}

	/**
	 * Handle preview cancellation
	 */
	function handlePreviewCancel() {
		console.log('[LorebookAIDialog] User cancelled preview');
		toast.info('Entries discarded', {
			description: 'No lorebook entries were added'
		});

		showPreview = false;
		previewEntries = [];
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Portal>
		<Dialog.Overlay />
		<Dialog.Content class="flex h-[95vh] max-w-full flex-col p-4 md:h-[90vh] md:max-w-3xl md:p-6">
			<Dialog.Header class="flex-shrink-0">
				<Dialog.Title class="flex items-center gap-2">
					<Sparkles class="h-5 w-5" />
					Lorebook AI Assistant
				</Dialog.Title>
				<Dialog.Description>
					Use AI to generate, enhance, and refine your lorebook entries
				</Dialog.Description>
			</Dialog.Header>

			<div class="-mx-2 flex-1 space-y-4 overflow-y-auto px-2 py-4">
				<!-- API Key Check -->
				{#if !aiSettings.hasApiKey}
					<Alert.Root variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<Alert.Title>API Key Required</Alert.Title>
						<Alert.Description>
							Please configure your AI API settings in Settings before using the assistant.
						</Alert.Description>
					</Alert.Root>
				{:else}
					<!-- Workflow Tabs -->
					<Tabs.Root bind:value={activeTab} class="w-full">
						<Tabs.List class="grid w-full grid-cols-3">
							<Tabs.Trigger value="single">Single Entry</Tabs.Trigger>
							<Tabs.Trigger value="batch">Batch Generate</Tabs.Trigger>
							<Tabs.Trigger value="enhance">Enhance Lorebook</Tabs.Trigger>
						</Tabs.List>

						<!-- Single Entry Tab -->
						<Tabs.Content value="single" class="space-y-4">
							<div class="space-y-2">
								<Label for="single-topic">Topic</Label>
								<Textarea
									id="single-topic"
									placeholder="e.g., The Sword of Destiny&#10;&#10;You can also paste source text or descriptions here - the AI will extract the key information automatically."
									bind:value={singleTopic}
									disabled={isExecuting}
									class="min-h-[100px] resize-y"
								/>
								{#if singleTopic.length > 200}
									<Alert.Root>
										<AlertCircle class="h-4 w-4" />
										<Alert.Title>Long Source Text Detected</Alert.Title>
										<Alert.Description>
											<p class="text-xs">
												You've entered {singleTopic.length} characters. The AI will automatically extract
												the topic title and use the full text as source material.
											</p>
										</Alert.Description>
									</Alert.Root>
								{:else}
									<p class="text-xs text-muted-foreground">
										Enter a topic name, or paste source text to create a lorebook entry from
									</p>
								{/if}
							</div>

							<Button
								onclick={handleGenerateSingle}
								disabled={isExecuting || !singleTopic.trim()}
								class="w-full"
							>
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Generating...
								{:else}
									<Sparkles class="mr-2 h-4 w-4" />
									Generate Entry
								{/if}
							</Button>
						</Tabs.Content>

						<!-- Batch Generate Tab -->
						<Tabs.Content value="batch" class="space-y-4">
							<div class="grid gap-4">
								<div class="space-y-2">
									<Label for="batch-count">Number of Entries</Label>
									<Input
										id="batch-count"
										type="number"
										min="1"
										max="20"
										bind:value={batchCount}
										disabled={isExecuting}
									/>
								</div>

								<div class="space-y-2">
									<Label for="batch-theme">Theme (Optional)</Label>
									<Input
										id="batch-theme"
										placeholder="e.g., magical items, locations, factions"
										bind:value={batchTheme}
										disabled={isExecuting}
									/>
									<p class="text-xs text-muted-foreground">
										Leave empty for general world-building entries
									</p>
								</div>
							</div>

							<Button onclick={handleBatchGenerate} disabled={isExecuting} class="w-full">
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Generating...
								{:else}
									<Sparkles class="mr-2 h-4 w-4" />
									Generate {batchCount} Entries
								{/if}
							</Button>
						</Tabs.Content>

						<!-- Enhance Lorebook Tab -->
						<Tabs.Content value="enhance" class="space-y-4">
							<Alert.Root>
								<AlertCircle class="h-4 w-4" />
								<Alert.Title>Smart Enhancement</Alert.Title>
								<Alert.Description>
									The AI will analyze your character and existing lorebook to identify and fill
									important gaps in world-building coverage.
								</Alert.Description>
							</Alert.Root>

							<div class="space-y-2">
								<Label for="enhance-max">Maximum New Entries</Label>
								<Input
									id="enhance-max"
									type="number"
									min="1"
									max="20"
									bind:value={enhanceMaxEntries}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">
									AI will create up to this many entries based on identified gaps
								</p>
							</div>

							<Button onclick={handleEnhanceLorebook} disabled={isExecuting} class="w-full">
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Analyzing...
								{:else}
									<Sparkles class="mr-2 h-4 w-4" />
									Enhance Lorebook
								{/if}
							</Button>
						</Tabs.Content>
					</Tabs.Root>

					<!-- Progress Display -->
					{#if progress}
						<div class="space-y-2 rounded-lg border bg-muted/30 p-4">
							<div class="flex items-center justify-between">
								<p class="text-sm font-medium">{progress.message}</p>
								<span class="text-xs text-muted-foreground">
									{progress.currentStep}/{progress.totalSteps}
								</span>
							</div>
							<div class="h-2 w-full overflow-hidden rounded-full bg-secondary">
								<div
									class="h-full bg-primary transition-all duration-300"
									style="width: {progress.percentage}%"
								></div>
							</div>
							{#if progress.currentAction}
								<p class="text-xs text-muted-foreground">
									Executing: {progress.currentAction.toolName}
								</p>
							{/if}
						</div>
					{/if}

					<!-- Result Display -->
					{#if result}
						<div class="space-y-3 rounded-lg border p-4">
							{#if result.success}
								<div class="flex items-center gap-2 text-green-600 dark:text-green-400">
									<Check class="h-5 w-5" />
									<h4 class="font-semibold">Workflow Completed Successfully</h4>
								</div>
								<div class="space-y-3">
									<p class="text-sm text-muted-foreground">
										Executed {result.toolExecutions.length} actions in {Math.round(
											(result.totalTimeMs ?? 0) / 1000
										)}s
									</p>
									<WorkflowSummary toolExecutions={result.toolExecutions} />
								</div>
							{:else}
								<div class="flex items-center gap-2 text-destructive">
									<X class="h-5 w-5" />
									<h4 class="font-semibold">Workflow Failed</h4>
								</div>
								<p class="text-sm text-muted-foreground">{result.error}</p>
							{/if}
						</div>
					{/if}

					<!-- Error Display -->
					{#if error && !result}
						<Alert.Root variant="destructive">
							<AlertCircle class="h-4 w-4" />
							<Alert.Title>Error</Alert.Title>
							<Alert.Description>
								<div class="space-y-2">
									<p>{error}</p>
									<p class="mt-2 text-xs">
										Check the browser console (F12) for detailed error information and debug logs.
									</p>
								</div>
							</Alert.Description>
						</Alert.Root>
					{/if}

					<!-- Debug Panel -->
					{#if aiSettings.securitySettings.showDebugInfo && result}
						<div
							class="space-y-3 rounded-lg border border-amber-500 bg-amber-50 p-4 dark:bg-amber-950"
						>
							<div class="flex items-center gap-2 text-amber-900 dark:text-amber-100">
								<AlertCircle class="h-5 w-5" />
								<h4 class="font-semibold">Debug Information</h4>
							</div>

							<div class="space-y-3 text-sm">
								<!-- Plan Summary -->
								{#if result.plan}
									<div class="space-y-2">
										<h5 class="font-medium">Plan</h5>
										<div class="rounded bg-amber-100 p-3 dark:bg-amber-900">
											<p class="text-xs"><strong>Goal:</strong> {result.plan.goal}</p>
											<p class="mt-1 text-xs">
												<strong>Reasoning:</strong>
												{result.plan.reasoning}
											</p>
											<p class="mt-1 text-xs">
												<strong>Actions:</strong>
												{result.plan.totalSteps} steps
											</p>
										</div>
									</div>
								{/if}

								<!-- Tool Executions -->
								{#if result.toolExecutions && result.toolExecutions.length > 0}
									<div class="space-y-2">
										<h5 class="font-medium">Tool Executions</h5>
										<div class="space-y-2">
											{#each result.toolExecutions as execution, i}
												<div
													class="rounded border border-amber-200 bg-white p-2 dark:border-amber-800 dark:bg-amber-950"
												>
													<div class="mb-1 flex items-center justify-between">
														<span class="font-mono text-xs font-semibold">
															{i + 1}. {execution.toolName}
														</span>
														{#if execution.success}
															<Check class="h-3 w-3 text-green-600 dark:text-green-400" />
														{:else}
															<X class="h-3 w-3 text-red-600 dark:text-red-400" />
														{/if}
													</div>

													<div class="space-y-1 text-xs">
														<details class="cursor-pointer">
															<summary class="text-amber-700 dark:text-amber-300">
																Parameters
															</summary>
															<pre
																class="mt-1 overflow-x-auto rounded bg-amber-50 p-2 text-[10px] dark:bg-amber-900">{JSON.stringify(
																	execution.parameters,
																	null,
																	2
																)}</pre>
														</details>

														{#if execution.success}
															<details class="cursor-pointer">
																<summary class="text-amber-700 dark:text-amber-300">
																	Result
																</summary>
																<pre
																	class="mt-1 overflow-x-auto rounded bg-amber-50 p-2 text-[10px] dark:bg-amber-900">{JSON.stringify(
																		execution.result,
																		null,
																		2
																	)}</pre>
															</details>
														{:else}
															<p class="text-red-600 dark:text-red-400">
																<strong>Error:</strong>
																{execution.error}
															</p>
														{/if}

														<p class="text-amber-600 dark:text-amber-400">
															<strong>Time:</strong>
															{execution.executionTimeMs}ms
														</p>
													</div>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								<!-- Timing -->
								<div class="rounded bg-amber-100 p-2 text-xs dark:bg-amber-900">
									<strong>Total Execution Time:</strong>
									{result.totalTimeMs ?? 0}ms
								</div>
							</div>
						</div>
					{/if}
				{/if}
			</div>

			<Dialog.Footer class="mt-4 flex-shrink-0">
				<Button variant="outline" onclick={handleClose} disabled={isExecuting}>
					{isExecuting ? 'Close' : 'Done'}
				</Button>
				{#if isExecuting}
					<Button variant="destructive" onclick={handleCancel}>Cancel</Button>
				{/if}
			</Dialog.Footer>
		</Dialog.Content>
	</Dialog.Portal>
</Dialog.Root>

<!-- Lorebook Preview Dialog (rendered outside to avoid nested dialog issues) -->
<LorebookPreviewDialog
	bind:open={showPreview}
	entries={previewEntries}
	onapprove={handlePreviewApprove}
	oncancel={handlePreviewCancel}
/>
