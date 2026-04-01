<script lang="ts">
	import { resolve } from '$app/paths';
	/**
	 * Research Dialog
	 *
	 * UI for executing web research workflows using Firecrawl API.
	 * Allows researching topics, crawling websites, and creating lorebook entries from web data.
	 */

	import { createEventDispatcher } from 'svelte';
	import { characterStore } from '$lib/stores/character.svelte';
	import { aiSettings } from '$lib/stores/ai-settings.svelte';
	import { researchSettings } from '$lib/stores/research-settings.svelte';
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
	import { AlertCircle, Loader2, Globe, Check, X, ExternalLink } from 'lucide-svelte';
	import type { LorebookEntry } from '$lib/types/character';
	import { toast } from 'svelte-sonner';

	import { ResearchAgentFactory } from '$lib/utils/agentic';
	import type { WorkflowProgress, WorkflowResult } from '$lib/utils/agentic';
	import {
		quickSearchWorkflow,
		deepResearchWorkflow,
		topicResearchWorkflow,
		currentEventsWorkflow,
		settingResearchWorkflow
	} from '$lib/utils/agentic/research-workflows';

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	const dispatch = createEventDispatcher<{ close: void }>();

	// Workflow state
	let activeTab = $state<string>('quick');
	let isExecuting = $state(false);
	let progress = $state<WorkflowProgress | null>(null);
	let result = $state<WorkflowResult | null>(null);
	let error = $state<string | null>(null);

	// Preview state
	let showPreview = $state(false);
	let previewEntries = $state<LorebookEntry[]>([]);

	// Quick Search inputs
	let quickSearchTopic = $state('');
	let quickSearchMaxResults = $state(3);

	// Deep Research inputs
	let deepResearchUrl = $state('');
	let deepResearchMaxPages = $state(10);
	let deepResearchMaxEntries = $state(5);

	// Topic Research inputs
	let topicResearchTopic = $state('');
	let topicResearchSources = $state('');
	let topicResearchMaxEntries = $state(5);

	// Current Events inputs
	let currentEventsQuery = $state('');
	let currentEventsMaxEntries = $state(5);

	// Setting Research inputs
	let settingResearchSetting = $state('');
	let settingResearchAspects = $state('');
	let settingResearchMaxEntries = $state(5);

	/**
	 * Execute a research workflow
	 */
	async function executeWorkflow(goal: string, context: Record<string, unknown>) {
		const apiKey = aiSettings.getApiKey();

		if (!apiKey || !aiSettings.provider) {
			error = 'Please configure your AI settings first';
			console.error('[ResearchDialog] API key or provider not configured');
			return;
		}

		if (!researchSettings.hasApiKey) {
			error = 'Please configure your Firecrawl API key in Research Settings';
			console.error('[ResearchDialog] Firecrawl API key not configured');
			return;
		}

		isExecuting = true;
		error = null;
		result = null;
		progress = null;

		console.log('[ResearchDialog] Starting research workflow execution');
		console.log('[ResearchDialog] Goal:', goal);
		console.log('[ResearchDialog] Context:', context);

		try {
			// Create AI provider
			const provider = createProvider(aiSettings.provider, apiKey);
			console.log('[ResearchDialog] Provider created:', aiSettings.provider);

			// Create research agent
			const agent = ResearchAgentFactory.createResearchAgent(
				provider,
				ResearchAgentFactory.getResearchConfig()
			);
			console.log('[ResearchDialog] Research agent created');

			// Execute workflow with progress callback
			const workflowResult = await agent.executeWorkflowMultiStage(goal, context, (p) => {
				progress = p;
			});

			result = workflowResult;
			console.log('[ResearchDialog] Workflow result:', workflowResult);

			if (!workflowResult.success) {
				const errorMsg = workflowResult.error || 'Research workflow failed';
				error = errorMsg;
				console.error('[ResearchDialog] Workflow failed:', errorMsg);
				console.error('[ResearchDialog] Tool executions:', workflowResult.toolExecutions);
			} else {
				console.log('[ResearchDialog] Research workflow completed successfully');

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
						console.log('[ResearchDialog] Found', allEntries.length, 'entries, showing preview');

						// Entries are NOT added to character yet - they're just validated and returned by the tool
						// User will review them in preview, then we add only the approved ones

						// Close research dialog and show preview (mutually exclusive)
						previewEntries = allEntries;
						open = false; // Close research dialog first

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
			console.error('[ResearchDialog] Exception during workflow:', errorMsg);
			console.error('[ResearchDialog] Stack:', e instanceof Error ? e.stack : 'N/A');
		} finally {
			isExecuting = false;
		}
	}

	/**
	 * Handle preview approval - create the approved entries
	 */
	function handlePreviewApprove(approvedEntries: LorebookEntry[]) {
		console.log('[ResearchDialog] User approved', approvedEntries.length, 'entries');

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
		console.log('[ResearchDialog] User cancelled preview');
		toast.info('Entries discarded', {
			description: 'No lorebook entries were added'
		});

		showPreview = false;
		previewEntries = [];
	}

	/**
	 * Quick Search workflow
	 */
	async function handleQuickSearch() {
		if (!quickSearchTopic.trim()) {
			error = 'Please enter a topic to search';
			return;
		}

		const workflow = quickSearchWorkflow(quickSearchTopic, {
			maxResults: quickSearchMaxResults
		});

		await executeWorkflow(workflow.goal, workflow.context);
	}

	/**
	 * Deep Research workflow
	 */
	async function handleDeepResearch() {
		if (!deepResearchUrl.trim()) {
			error = 'Please enter a URL to crawl';
			return;
		}

		// Validate URL
		try {
			new URL(deepResearchUrl);
		} catch {
			error = 'Please enter a valid URL (e.g., https://example.com)';
			return;
		}

		const workflow = deepResearchWorkflow(deepResearchUrl, {
			maxPages: deepResearchMaxPages,
			maxEntries: deepResearchMaxEntries
		});

		await executeWorkflow(workflow.goal, workflow.context);
	}

	/**
	 * Topic Research workflow
	 */
	async function handleTopicResearch() {
		if (!topicResearchTopic.trim()) {
			error = 'Please enter a topic to research';
			return;
		}

		// Parse sources (comma-separated URLs)
		const sources = topicResearchSources
			.split(',')
			.map((s) => s.trim())
			.filter((s) => s.length > 0);

		const workflow = topicResearchWorkflow(
			topicResearchTopic,
			sources.length > 0 ? sources : undefined,
			{ maxEntries: topicResearchMaxEntries }
		);

		await executeWorkflow(workflow.goal, workflow.context);
	}

	/**
	 * Current Events workflow
	 */
	async function handleCurrentEvents() {
		if (!currentEventsQuery.trim()) {
			error = 'Please enter a query for current events';
			return;
		}

		const workflow = currentEventsWorkflow(currentEventsQuery, {
			maxEntries: currentEventsMaxEntries
		});

		await executeWorkflow(workflow.goal, workflow.context);
	}

	/**
	 * Setting Research workflow
	 */
	async function handleSettingResearch() {
		if (!settingResearchSetting.trim()) {
			error = 'Please enter a setting to research';
			return;
		}

		// Parse aspects (comma-separated)
		const aspects = settingResearchAspects
			.split(',')
			.map((s) => s.trim())
			.filter((s) => s.length > 0);

		const workflow = settingResearchWorkflow(
			settingResearchSetting,
			aspects.length > 0 ? aspects : undefined,
			{ maxEntries: settingResearchMaxEntries }
		);

		await executeWorkflow(workflow.goal, workflow.context);
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
			quickSearchTopic = '';
			deepResearchUrl = '';
			topicResearchTopic = '';
			topicResearchSources = '';
			currentEventsQuery = '';
			settingResearchSetting = '';
			settingResearchAspects = '';
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
</script>

<Dialog.Root bind:open>
	<Dialog.Portal>
		<Dialog.Overlay />
		<Dialog.Content class="flex h-[95vh] max-w-full flex-col p-4 md:h-[90vh] md:max-w-4xl md:p-6">
			<Dialog.Header class="flex-shrink-0">
				<Dialog.Title class="flex items-center gap-2">
					<Globe class="h-5 w-5" />
					Web Research Assistant
				</Dialog.Title>
				<Dialog.Description>
					Research information from the web and create lorebook entries using Firecrawl
				</Dialog.Description>
			</Dialog.Header>

			<div class="-mx-2 flex-1 space-y-4 overflow-y-auto px-2 py-4">
				<!-- API Key Checks -->
				{#if !aiSettings.hasApiKey}
					<Alert.Root variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<Alert.Title>AI API Key Required</Alert.Title>
						<Alert.Description>
							Please configure your AI API settings in Settings → AI Settings before using research.
						</Alert.Description>
					</Alert.Root>
				{:else if !researchSettings.hasApiKey}
					<Alert.Root variant="destructive">
						<AlertCircle class="h-4 w-4" />
						<Alert.Title>Firecrawl API Key Required</Alert.Title>
						<Alert.Description>
							Please configure your Firecrawl API key in Settings → AI Settings before using web
							research.
							<a
								href={resolve("/settings/ai")}
								class="ml-2 inline-flex items-center gap-1 text-primary hover:underline"
							>
								Configure Now
								<ExternalLink class="h-3 w-3" />
							</a>
						</Alert.Description>
					</Alert.Root>
				{:else}
					<!-- Workflow Tabs -->
					<Tabs.Root bind:value={activeTab} class="w-full">
						<Tabs.List class="grid w-full grid-cols-2 gap-1 md:grid-cols-3 lg:grid-cols-5">
							<Tabs.Trigger value="quick" class="truncate text-xs md:text-sm"
								>Quick Search</Tabs.Trigger
							>
							<Tabs.Trigger value="deep" class="truncate text-xs md:text-sm"
								>Deep Research</Tabs.Trigger
							>
							<Tabs.Trigger value="topic" class="truncate text-xs md:text-sm"
								>Topic Research</Tabs.Trigger
							>
							<Tabs.Trigger value="events" class="truncate text-xs md:text-sm"
								>Current Events</Tabs.Trigger
							>
							<Tabs.Trigger value="setting" class="truncate text-xs md:text-sm"
								>Setting</Tabs.Trigger
							>
						</Tabs.List>

						<!-- Quick Search Tab -->
						<Tabs.Content value="quick" class="space-y-4">
							<Alert.Root>
								<AlertCircle class="h-4 w-4" />
								<Alert.Title>Quick Search</Alert.Title>
								<Alert.Description>
									Search for a topic and create a single lorebook entry from the most relevant
									result.
								</Alert.Description>
							</Alert.Root>

							<div class="space-y-2">
								<Label for="quick-topic">Topic</Label>
								<Input
									id="quick-topic"
									placeholder="e.g., Byzantine Empire"
									bind:value={quickSearchTopic}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">
									Enter a topic to search and create a lorebook entry for
								</p>
							</div>

							<div class="space-y-2">
								<Label for="quick-max-results">Max Search Results</Label>
								<Input
									id="quick-max-results"
									type="number"
									min="1"
									max="10"
									bind:value={quickSearchMaxResults}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">
									Number of search results to consider (default: 3)
								</p>
							</div>

							<Button
								onclick={handleQuickSearch}
								disabled={isExecuting || !quickSearchTopic.trim()}
								class="w-full"
							>
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Researching...
								{:else}
									<Globe class="mr-2 h-4 w-4" />
									Search & Create Entry
								{/if}
							</Button>
						</Tabs.Content>

						<!-- Deep Research Tab -->
						<Tabs.Content value="deep" class="space-y-4">
							<Alert.Root>
								<AlertCircle class="h-4 w-4" />
								<Alert.Title>Deep Research</Alert.Title>
								<Alert.Description>
									Crawl a website and create multiple lorebook entries from discovered content. Best
									for wikis and documentation sites.
								</Alert.Description>
							</Alert.Root>

							<div class="space-y-2">
								<Label for="deep-url">Starting URL</Label>
								<Input
									id="deep-url"
									placeholder="https://example.com/wiki"
									bind:value={deepResearchUrl}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">The website to crawl for information</p>
							</div>

							<div class="grid grid-cols-2 gap-4">
								<div class="space-y-2">
									<Label for="deep-max-pages">Max Pages</Label>
									<Input
										id="deep-max-pages"
										type="number"
										min="1"
										max="20"
										bind:value={deepResearchMaxPages}
										disabled={isExecuting}
									/>
								</div>

								<div class="space-y-2">
									<Label for="deep-max-entries">Max Entries</Label>
									<Input
										id="deep-max-entries"
										type="number"
										min="1"
										max="20"
										bind:value={deepResearchMaxEntries}
										disabled={isExecuting}
									/>
								</div>
							</div>

							<Button
								onclick={handleDeepResearch}
								disabled={isExecuting || !deepResearchUrl.trim()}
								class="w-full"
							>
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Crawling...
								{:else}
									<Globe class="mr-2 h-4 w-4" />
									Crawl & Create Entries
								{/if}
							</Button>
						</Tabs.Content>

						<!-- Topic Research Tab -->
						<Tabs.Content value="topic" class="space-y-4">
							<Alert.Root>
								<AlertCircle class="h-4 w-4" />
								<Alert.Title>Topic Research</Alert.Title>
								<Alert.Description>
									Research a topic across multiple sources and synthesize into comprehensive
									lorebook entries.
								</Alert.Description>
							</Alert.Root>

							<div class="space-y-2">
								<Label for="topic-topic">Topic</Label>
								<Input
									id="topic-topic"
									placeholder="e.g., Quantum Computing"
									bind:value={topicResearchTopic}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">The topic to research in depth</p>
							</div>

							<div class="space-y-2">
								<Label for="topic-sources">Sources (Optional)</Label>
								<Textarea
									id="topic-sources"
									placeholder="https://example.com, https://another-site.com (comma-separated)"
									bind:value={topicResearchSources}
									disabled={isExecuting}
									rows={2}
								/>
								<p class="text-xs text-muted-foreground">
									Specific URLs to research from. Leave empty to search automatically.
								</p>
							</div>

							<div class="space-y-2">
								<Label for="topic-max-entries">Max Entries</Label>
								<Input
									id="topic-max-entries"
									type="number"
									min="1"
									max="20"
									bind:value={topicResearchMaxEntries}
									disabled={isExecuting}
								/>
							</div>

							<Button
								onclick={handleTopicResearch}
								disabled={isExecuting || !topicResearchTopic.trim()}
								class="w-full"
							>
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Researching...
								{:else}
									<Globe class="mr-2 h-4 w-4" />
									Research & Synthesize
								{/if}
							</Button>
						</Tabs.Content>

						<!-- Current Events Tab -->
						<Tabs.Content value="events" class="space-y-4">
							<Alert.Root>
								<AlertCircle class="h-4 w-4" />
								<Alert.Title>Current Events</Alert.Title>
								<Alert.Description>
									Research recent news and events to create timely lorebook entries with up-to-date
									information.
								</Alert.Description>
							</Alert.Root>

							<div class="space-y-2">
								<Label for="events-query">Query</Label>
								<Input
									id="events-query"
									placeholder="e.g., Palestine current affairs 2024"
									bind:value={currentEventsQuery}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">
									Current events or news topic to research
								</p>
							</div>

							<div class="space-y-2">
								<Label for="events-max-entries">Max Entries</Label>
								<Input
									id="events-max-entries"
									type="number"
									min="1"
									max="20"
									bind:value={currentEventsMaxEntries}
									disabled={isExecuting}
								/>
							</div>

							<Button
								onclick={handleCurrentEvents}
								disabled={isExecuting || !currentEventsQuery.trim()}
								class="w-full"
							>
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Researching...
								{:else}
									<Globe class="mr-2 h-4 w-4" />
									Research Current Events
								{/if}
							</Button>
						</Tabs.Content>

						<!-- Setting Research Tab -->
						<Tabs.Content value="setting" class="space-y-4">
							<Alert.Root>
								<AlertCircle class="h-4 w-4" />
								<Alert.Title>Setting Research</Alert.Title>
								<Alert.Description>
									Research a real-world location, time period, or setting for worldbuilding and
									roleplay context.
								</Alert.Description>
							</Alert.Root>

							<div class="space-y-2">
								<Label for="setting-setting">Setting</Label>
								<Input
									id="setting-setting"
									placeholder="e.g., Victorian London, Ancient Egypt"
									bind:value={settingResearchSetting}
									disabled={isExecuting}
								/>
								<p class="text-xs text-muted-foreground">
									The setting, time period, or location to research
								</p>
							</div>

							<div class="space-y-2">
								<Label for="setting-aspects">Focus Aspects (Optional)</Label>
								<Textarea
									id="setting-aspects"
									placeholder="e.g., daily life, culture, technology (comma-separated)"
									bind:value={settingResearchAspects}
									disabled={isExecuting}
									rows={2}
								/>
								<p class="text-xs text-muted-foreground">
									Specific aspects to focus on. Default: daily life, culture, technology, politics,
									geography
								</p>
							</div>

							<div class="space-y-2">
								<Label for="setting-max-entries">Max Entries</Label>
								<Input
									id="setting-max-entries"
									type="number"
									min="1"
									max="20"
									bind:value={settingResearchMaxEntries}
									disabled={isExecuting}
								/>
							</div>

							<Button
								onclick={handleSettingResearch}
								disabled={isExecuting || !settingResearchSetting.trim()}
								class="w-full"
							>
								{#if isExecuting}
									<Loader2 class="mr-2 h-4 w-4 animate-spin" />
									Researching...
								{:else}
									<Globe class="mr-2 h-4 w-4" />
									Research Setting
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
						<div class="space-y-3 break-words rounded-lg border p-4">
							{#if result.success}
								<div class="flex items-center gap-2 text-green-600 dark:text-green-400">
									<Check class="h-5 w-5 flex-shrink-0" />
									<h4 class="font-semibold">Research Completed Successfully</h4>
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
									<X class="h-5 w-5 flex-shrink-0" />
									<h4 class="font-semibold">Research Failed</h4>
								</div>
								<p class="break-words text-sm text-muted-foreground">{result.error}</p>
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
									{result.totalTimeMs}ms
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
