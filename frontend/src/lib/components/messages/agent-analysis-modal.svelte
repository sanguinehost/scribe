<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Copy, Brain, Search, Sparkles, Clock as _Clock, AlertCircle } from 'lucide-svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import type { AgentAnalysisResponse } from '$lib/types';

	// Interface for execution log steps
	interface ExecutionStep {
		step_number: number;
		action_type: string;
		thought?: string;
		tokens_used?: number;
		duration_ms?: number;
		tool_call?: {
			tool_name: string;
			parameters: Record<string, unknown>;
		};
		result?: unknown;
		observations?: string;
	}

	interface ExecutionLog {
		steps: ExecutionStep[];
	}

	let {
		open = $bindable(false),
		messageId,
		sessionId
	}: {
		open: boolean;
		messageId: string;
		sessionId?: string;
	} = $props();

	let agentAnalysis = $state<AgentAnalysisResponse | null>(null);
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let hasFetched = $state(false);

	// Fetch agent analysis when modal opens
	$effect(() => {
		if (open && !hasFetched && !isLoading && !agentAnalysis) {
			fetchAgentAnalysis();
		}
	});

	async function fetchAgentAnalysis() {
		if (isLoading || !sessionId) return;

		isLoading = true;
		error = null;

		try {
			// Pass the messageId to fetch analysis specific to this message
			const result = await _apiClient.getAgentAnalysis(sessionId, undefined, messageId);

			if (result.isOk()) {
				const analyses = result.value;
				if (analyses && analyses.length > 0) {
					// Find analysis for this specific message, preferring pre_processing
					agentAnalysis = analyses.find((a) => a.analysis_type === 'pre_processing') || analyses[0];
				} else {
					error = 'No agent analysis performed for this message';
				}
				hasFetched = true;
			} else {
				error = result.error.message || 'Failed to load agent analysis';
			}
			hasFetched = true;
		} catch (err) {
			console.error('Error fetching agent analysis:', err);
			error = 'Failed to load agent analysis';
			hasFetched = true;
		} finally {
			isLoading = false;
		}
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
		} catch (err) {
			console.error('Failed to copy:', err);
		}
	}

	function handleOpenChange(newOpen: boolean) {
		open = newOpen;
		// Reset state when closing
		if (!newOpen) {
			agentAnalysis = null;
			error = null;
			isLoading = false;
			hasFetched = false;
		}
	}

	function getActionIcon(actionType: string) {
		switch (actionType) {
			case 'planning':
				return Brain;
			case 'search':
			case 'search_error':
				return Search;
			case 'synthesis':
				return Sparkles;
			default:
				return AlertCircle;
		}
	}

	function formatDuration(ms: number) {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(2)}s`;
	}

	interface ParsedContext {
		cognitiveContext: string[];
		lorebookEntries: string[];
		chronicleEvents: string[];
		chatHistory: string[];
		other: string[];
		totalItems: number;
	}

	function parseRetrievedContext(context: string): ParsedContext {
		const result: ParsedContext = {
			cognitiveContext: [],
			lorebookEntries: [],
			chronicleEvents: [],
			chatHistory: [],
			other: [],
			totalItems: 0
		};

		if (!context) return result;

		// Split by common section markers
		const lines = context.split('\n');
		let currentSection: 'cognitive' | 'lorebook' | 'chronicle' | 'chat' | 'other' = 'other';
		let currentEntry = '';

		for (const line of lines) {
			// Detect section markers
			if (
				line.includes('[COGNITIVE_CONTEXT]') ||
				line.includes('### Character Opinions') ||
				line.includes('### Entity Observations')
			) {
				if (currentEntry.trim()) {
					pushToSection(result, currentSection, currentEntry.trim());
				}
				currentSection = 'cognitive';
				currentEntry = line.replace('[COGNITIVE_CONTEXT]', '').trim();
			} else if (line.includes('[LOREBOOK]') || line.includes('Lorebook:')) {
				if (currentEntry.trim()) {
					pushToSection(result, currentSection, currentEntry.trim());
				}
				currentSection = 'lorebook';
				currentEntry = line.replace('[LOREBOOK]', '').trim();
			} else if (line.includes('[CHRONICLE]') || line.includes('Chronicle Event:')) {
				if (currentEntry.trim()) {
					pushToSection(result, currentSection, currentEntry.trim());
				}
				currentSection = 'chronicle';
				currentEntry = line.replace('[CHRONICLE]', '').trim();
			} else if (line.includes('[CHAT]') || line.includes('Previous Message:')) {
				if (currentEntry.trim()) {
					pushToSection(result, currentSection, currentEntry.trim());
				}
				currentSection = 'chat';
				currentEntry = line.replace('[CHAT]', '').trim();
			} else if (line.startsWith('- ') && currentSection !== 'other') {
				// Bullet point within a section - start new entry
				if (currentEntry.trim()) {
					pushToSection(result, currentSection, currentEntry.trim());
				}
				currentEntry = line.substring(2);
			} else if (line.trim()) {
				currentEntry += (currentEntry ? '\n' : '') + line;
			}
		}

		// Push final entry
		if (currentEntry.trim()) {
			pushToSection(result, currentSection, currentEntry.trim());
		}

		result.totalItems =
			result.cognitiveContext.length +
			result.lorebookEntries.length +
			result.chronicleEvents.length +
			result.chatHistory.length +
			result.other.length;

		return result;
	}

	function pushToSection(result: ParsedContext, section: string, entry: string) {
		switch (section) {
			case 'cognitive':
				result.cognitiveContext.push(entry);
				break;
			case 'lorebook':
				result.lorebookEntries.push(entry);
				break;
			case 'chronicle':
				result.chronicleEvents.push(entry);
				break;
			case 'chat':
				result.chatHistory.push(entry);
				break;
			default:
				result.other.push(entry);
		}
	}
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
	<Dialog.Content class="flex max-h-[85vh] max-w-5xl flex-col">
		<Dialog.Header class="flex flex-row items-center justify-between border-b pb-4">
			<div>
				<Dialog.Title class="flex items-center gap-2 text-lg font-semibold">
					<Brain class="h-5 w-5" />
					Agent Context Analysis
				</Dialog.Title>
				<Dialog.Description class="mt-1 text-sm text-muted-foreground">
					{#if agentAnalysis && agentAnalysis.message_id === messageId}
						View the agent's thought process and context retrieval for this message
					{:else}
						View the agent's thought process and context retrieval
					{/if}
				</Dialog.Description>
			</div>
			{#if agentAnalysis}
				<div class="flex items-center gap-2">
					<ButtonComponent
						variant="outline"
						size="sm"
						onclick={() => copyToClipboard(JSON.stringify(agentAnalysis, null, 2))}
						class="gap-2"
					>
						<Copy size={14} />
						Copy JSON
					</ButtonComponent>
				</div>
			{/if}
		</Dialog.Header>

		<div class="mt-4 min-h-0 flex-1 overflow-y-auto">
			{#if isLoading}
				<div class="flex items-center justify-center py-12">
					<div class="flex items-center gap-3 text-muted-foreground">
						<div
							class="h-5 w-5 animate-spin rounded-full border-2 border-current border-t-transparent"
						></div>
						Loading agent analysis...
					</div>
				</div>
			{:else if error}
				<div class="flex flex-col items-center justify-center py-12">
					<div class="mb-4 rounded-lg bg-destructive/10 p-4 text-center">
						<div class="mb-2 text-sm font-medium text-destructive">Error</div>
						<p class="text-sm text-muted-foreground">{error}</p>
					</div>
					<ButtonComponent
						variant="outline"
						onclick={() => {
							hasFetched = false;
							fetchAgentAnalysis();
						}}
						disabled={isLoading}
					>
						Retry
					</ButtonComponent>
				</div>
			{:else if agentAnalysis}
				<div class="space-y-4">
					<!-- Overview -->
					<div class="rounded-lg border bg-muted/20 p-4">
						<h3 class="mb-2 font-medium">Analysis Overview</h3>
						<div class="grid grid-cols-2 gap-4 text-sm">
							<div>
								<span class="text-muted-foreground">Mode:</span>
								<span class="ml-2 font-medium">
									{agentAnalysis.analysis_type === 'pre_processing'
										? 'Pre-processing'
										: 'Post-processing'}
								</span>
							</div>
							{#if agentAnalysis.model_used}
								<div>
									<span class="text-muted-foreground">Model:</span>
									<span class="ml-2 font-medium">{agentAnalysis.model_used}</span>
								</div>
							{/if}
							{#if agentAnalysis.total_tokens_used}
								<div>
									<span class="text-muted-foreground">Total Tokens:</span>
									<span class="ml-2 font-medium">{agentAnalysis.total_tokens_used}</span>
								</div>
							{/if}
							{#if agentAnalysis.execution_time_ms}
								<div>
									<span class="text-muted-foreground">Execution Time:</span>
									<span class="ml-2 font-medium"
										>{formatDuration(agentAnalysis.execution_time_ms)}</span
									>
								</div>
							{/if}
						</div>
					</div>

					<!-- Agent Reasoning -->
					{#if agentAnalysis.agent_reasoning}
						<div class="rounded-lg border p-4">
							<h3 class="mb-2 flex items-center gap-2 font-medium">
								<Brain size={16} />
								Agent Reasoning
							</h3>
							<div class="rounded bg-muted/50 p-3">
								<p class="text-sm italic">"{agentAnalysis.agent_reasoning}"</p>
							</div>
						</div>
					{/if}

					<!-- Planned Searches -->
					{#if agentAnalysis.planned_searches && Array.isArray(agentAnalysis.planned_searches) && agentAnalysis.planned_searches.length > 0}
						<div class="rounded-lg border p-4">
							<h3 class="mb-3 font-medium">Planned Searches</h3>
							<div class="space-y-2">
								{#each agentAnalysis.planned_searches as search, i (i)}
									<div class="rounded border bg-background p-3">
										<div class="mb-1 flex items-center justify-between">
											<span class="text-sm font-medium">Search {i + 1}</span>
											{#if search.search_type}
												<span class="rounded bg-muted px-2 py-0.5 text-xs"
													>{search.search_type}</span
												>
											{/if}
										</div>
										<div class="text-sm">
											<div class="text-foreground/90">
												<span class="font-mono">"{search.query}"</span>
											</div>
											{#if search.reason}
												<div class="mt-1 text-muted-foreground">
													Reason: {search.reason}
												</div>
											{/if}
										</div>
									</div>
								{/each}
							</div>
						</div>
					{:else if agentAnalysis.planned_searches}
						<!-- If planned_searches exists but isn't an array, show raw data -->
						<div class="rounded-lg border p-4">
							<h3 class="mb-3 font-medium">Planned Searches</h3>
							<pre class="overflow-x-auto rounded bg-muted/20 p-2 text-xs">
{JSON.stringify(agentAnalysis.planned_searches, null, 2)}</pre>
						</div>
					{/if}

					<!-- Execution Steps -->
					{#if agentAnalysis.execution_log}
						<div class="rounded-lg border p-4">
							<h3 class="mb-3 font-medium">Execution Log</h3>
							{#if (agentAnalysis.execution_log as ExecutionLog)?.steps && Array.isArray((agentAnalysis.execution_log as ExecutionLog).steps)}
								<div class="space-y-3">
									{#each (agentAnalysis.execution_log as ExecutionLog).steps as step, i (i)}
										{@const Icon = getActionIcon(step.action_type)}
										<div class="rounded border bg-background p-4">
											<div class="mb-2 flex items-center justify-between">
												<div class="flex items-center gap-2">
													<Icon size={16} />
													<span class="font-medium">
														Step {step.step_number}: {step.action_type.replace('_', ' ')}
													</span>
												</div>
												<div class="flex items-center gap-3 text-xs text-muted-foreground">
													{#if step.tokens_used}<span>{step.tokens_used} tokens</span>{/if}
													{#if step.duration_ms}<span>{formatDuration(step.duration_ms)}</span>{/if}
												</div>
											</div>

											<!-- Step thought -->
											{#if step.thought}
												<div class="mb-2 rounded bg-muted/30 p-2">
													<p class="text-sm italic">"{step.thought}"</p>
												</div>
											{/if}

											<!-- Tool call if present -->
											{#if step.tool_call}
												<details class="text-sm">
													<summary
														class="cursor-pointer text-muted-foreground hover:text-foreground"
													>
														Tool Call: {step.tool_call.tool_name}
													</summary>
													<pre class="mt-2 overflow-x-auto rounded bg-muted/20 p-2 text-xs">
{JSON.stringify(step.tool_call.parameters, null, 2)}</pre>
												</details>
											{/if}

											<!-- Results if present -->
											{#if step.result}
												<details class="mt-2 text-sm">
													<summary
														class="cursor-pointer text-muted-foreground hover:text-foreground"
													>
														Results
													</summary>
													<pre class="mt-2 overflow-x-auto rounded bg-muted/20 p-2 text-xs">
{JSON.stringify(step.result, null, 2)}</pre>
												</details>
											{/if}
										</div>
									{/each}
								</div>
							{:else}
								<!-- Raw execution log if not in expected format -->
								<pre class="overflow-x-auto rounded bg-muted/20 p-2 text-xs">
{JSON.stringify(agentAnalysis.execution_log, null, 2)}</pre>
							{/if}
						</div>
					{/if}

					<!-- Retrieved Context -->
					{#if agentAnalysis.retrieved_context}
						{@const parsedContext = parseRetrievedContext(agentAnalysis.retrieved_context)}
						<div class="space-y-3 rounded-lg border p-4">
							<h3 class="flex items-center gap-2 font-medium">
								<Search size={16} />
								Retrieved Context
								<span class="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
									{parsedContext.totalItems} items
								</span>
							</h3>

							<!-- Cognitive Context (Opinions/Observations) -->
							{#if parsedContext.cognitiveContext.length > 0}
								<details class="rounded border bg-purple-500/5" open>
									<summary
										class="flex cursor-pointer items-center gap-2 p-3 text-sm font-medium hover:bg-muted/50"
									>
										<Brain size={14} class="text-purple-500" />
										<span>Cognitive Memory</span>
										<span
											class="ml-auto rounded bg-purple-500/20 px-1.5 py-0.5 text-xs text-purple-600 dark:text-purple-400"
										>
											{parsedContext.cognitiveContext.length}
										</span>
									</summary>
									<div class="space-y-1 border-t p-3">
										{#each parsedContext.cognitiveContext as item, i (i)}
											<div class="rounded bg-muted/30 p-2 text-sm">
												<p class="whitespace-pre-wrap">{item}</p>
											</div>
										{/each}
									</div>
								</details>
							{/if}

							<!-- Lorebook Entries -->
							{#if parsedContext.lorebookEntries.length > 0}
								<details class="rounded border bg-amber-500/5">
									<summary
										class="flex cursor-pointer items-center gap-2 p-3 text-sm font-medium hover:bg-muted/50"
									>
										<Search size={14} class="text-amber-500" />
										<span>Lorebook Entries</span>
										<span
											class="ml-auto rounded bg-amber-500/20 px-1.5 py-0.5 text-xs text-amber-600 dark:text-amber-400"
										>
											{parsedContext.lorebookEntries.length}
										</span>
									</summary>
									<div class="space-y-1 border-t p-3">
										{#each parsedContext.lorebookEntries as item, i (i)}
											<div class="rounded bg-muted/30 p-2 text-sm">
												<p class="whitespace-pre-wrap">{item}</p>
											</div>
										{/each}
									</div>
								</details>
							{/if}

							<!-- Chronicle Events -->
							{#if parsedContext.chronicleEvents.length > 0}
								<details class="rounded border bg-blue-500/5">
									<summary
										class="flex cursor-pointer items-center gap-2 p-3 text-sm font-medium hover:bg-muted/50"
									>
										<Search size={14} class="text-blue-500" />
										<span>Chronicle Events</span>
										<span
											class="ml-auto rounded bg-blue-500/20 px-1.5 py-0.5 text-xs text-blue-600 dark:text-blue-400"
										>
											{parsedContext.chronicleEvents.length}
										</span>
									</summary>
									<div class="space-y-1 border-t p-3">
										{#each parsedContext.chronicleEvents as item, i (i)}
											<div class="rounded bg-muted/30 p-2 text-sm">
												<p class="whitespace-pre-wrap">{item}</p>
											</div>
										{/each}
									</div>
								</details>
							{/if}

							<!-- Chat History -->
							{#if parsedContext.chatHistory.length > 0}
								<details class="rounded border bg-green-500/5">
									<summary
										class="flex cursor-pointer items-center gap-2 p-3 text-sm font-medium hover:bg-muted/50"
									>
										<Search size={14} class="text-green-500" />
										<span>Chat History</span>
										<span
											class="ml-auto rounded bg-green-500/20 px-1.5 py-0.5 text-xs text-green-600 dark:text-green-400"
										>
											{parsedContext.chatHistory.length}
										</span>
									</summary>
									<div class="space-y-1 border-t p-3">
										{#each parsedContext.chatHistory as item, i (i)}
											<div class="rounded bg-muted/30 p-2 text-sm">
												<p class="whitespace-pre-wrap">{item}</p>
											</div>
										{/each}
									</div>
								</details>
							{/if}

							<!-- Other/Unparsed Context -->
							{#if parsedContext.other.length > 0}
								<details class="rounded border">
									<summary
										class="flex cursor-pointer items-center gap-2 p-3 text-sm font-medium hover:bg-muted/50"
									>
										<Search size={14} class="text-muted-foreground" />
										<span>Other Context</span>
										<span
											class="ml-auto rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
										>
											{parsedContext.other.length}
										</span>
									</summary>
									<div class="border-t p-3">
										<p class="whitespace-pre-wrap text-sm">{parsedContext.other.join('\n\n')}</p>
									</div>
								</details>
							{/if}
						</div>
					{/if}

					<!-- Final Summary -->
					{#if agentAnalysis.analysis_summary}
						<div class="rounded-lg border bg-primary/5 p-4">
							<h3 class="mb-2 flex items-center gap-2 font-medium">
								<Sparkles size={16} />
								Context Summary
							</h3>
							<p class="text-sm">{agentAnalysis.analysis_summary}</p>
						</div>
					{/if}
				</div>
			{:else}
				<div class="flex items-center justify-center py-12">
					<div class="text-muted-foreground">No data loaded</div>
				</div>
			{/if}
		</div>
	</Dialog.Content>
</Dialog.Root>
