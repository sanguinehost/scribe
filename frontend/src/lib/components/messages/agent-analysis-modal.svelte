<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Copy, Brain, Search, Sparkles, Clock, AlertCircle } from 'lucide-svelte';
	import { apiClient } from '$lib/api';

	let {
		open = $bindable(false),
		messageId,
		sessionId
	}: {
		open: boolean;
		messageId: string;
		sessionId?: string;
	} = $props();

	let agentAnalysis = $state<any | null>(null);
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
		if (isLoading) return;

		isLoading = true;
		error = null;

		try {
			// TODO: Implement API endpoint for fetching agent analysis
			// const result = await apiClient.getAgentAnalysis(messageId);
			// if (result.isOk()) {
			// 	agentAnalysis = result.value;
			// 	hasFetched = true;
			// } else {
			// 	error = result.error.message;
			// }
			
			// Mock data for development
			agentAnalysis = {
				mode: 'pre_processing',
				model_used: 'gemini-2.5-flash-lite',
				agent_reasoning: 'I noticed the user mentioned "the dragon we fought last week". I should search for recent dragon-related events and battles to provide proper context.',
				planned_searches: [
					{
						query: 'dragon battle',
						reason: 'User referenced a dragon battle from last week',
						search_type: 'chronicles'
					},
					{
						query: 'Drakon fire',
						reason: 'The dragon was named Drakon, searching for specific details',
						search_type: 'all'
					}
				],
				execution_log: {
					steps: [
						{
							step_number: 1,
							timestamp: new Date().toISOString(),
							action_type: 'planning',
							thought: 'Analyzing conversation for context needs. User mentioned past dragon battle.',
							tokens_used: 125,
							duration_ms: 342,
							result: {
								planned_searches: 2
							}
						},
						{
							step_number: 2,
							timestamp: new Date().toISOString(),
							action_type: 'search',
							thought: 'Searching for "dragon battle" in chronicles',
							tool_call: {
								tool_name: 'search_knowledge_base',
								parameters: {
									query: 'dragon battle',
									search_type: 'chronicles',
									limit: 10
								}
							},
							tokens_used: 45,
							duration_ms: 567,
							result: {
								total_results: 3,
								top_match: 'The party engaged Drakon the Red in fierce combat...'
							}
						},
						{
							step_number: 3,
							timestamp: new Date().toISOString(),
							action_type: 'synthesis',
							thought: 'Combining search results into coherent context',
							tokens_used: 210,
							duration_ms: 445,
							result: {
								summary_length: 342
							}
						}
					],
					total_duration_ms: 1354
				},
				analysis_summary: 'Found relevant context: The party fought Drakon the Red, an ancient fire dragon, seven days ago in the Scorched Peaks. The battle resulted in victory but left the wizard badly injured. The dragon\'s hoard contained the Crystal of Eternal Flame.',
				total_tokens_used: 380,
				execution_time_ms: 1354
			};
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
					View the agent's thought process and context retrieval
				</Dialog.Description>
			</div>
			{#if agentAnalysis}
				<div class="flex items-center gap-2">
					<Button 
						variant="outline" 
						size="sm" 
						onclick={() => copyToClipboard(JSON.stringify(agentAnalysis, null, 2))} 
						class="gap-2"
					>
						<Copy size={14} />
						Copy JSON
					</Button>
				</div>
			{/if}
		</Dialog.Header>

		<div class="mt-4 flex-1 overflow-y-auto min-h-0">
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
					<Button
						variant="outline"
						onclick={() => {
							hasFetched = false;
							fetchAgentAnalysis();
						}}
						disabled={isLoading}
					>
						Retry
					</Button>
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
									{agentAnalysis.mode === 'pre_processing' ? 'Pre-processing' : 'Post-processing'}
								</span>
							</div>
							<div>
								<span class="text-muted-foreground">Model:</span>
								<span class="ml-2 font-medium">{agentAnalysis.model_used}</span>
							</div>
							<div>
								<span class="text-muted-foreground">Total Tokens:</span>
								<span class="ml-2 font-medium">{agentAnalysis.total_tokens_used}</span>
							</div>
							<div>
								<span class="text-muted-foreground">Execution Time:</span>
								<span class="ml-2 font-medium">{formatDuration(agentAnalysis.execution_time_ms)}</span>
							</div>
						</div>
					</div>

					<!-- Agent Reasoning -->
					<div class="rounded-lg border p-4">
						<h3 class="mb-2 flex items-center gap-2 font-medium">
							<Brain size={16} />
							Agent Reasoning
						</h3>
						<div class="rounded bg-muted/50 p-3">
							<p class="text-sm italic">"{agentAnalysis.agent_reasoning}"</p>
						</div>
					</div>

					<!-- Planned Searches -->
					{#if agentAnalysis.planned_searches?.length > 0}
						<div class="rounded-lg border p-4">
							<h3 class="mb-3 font-medium">Planned Searches</h3>
							<div class="space-y-2">
								{#each agentAnalysis.planned_searches as search, i}
									<div class="rounded border bg-background p-3">
										<div class="mb-1 flex items-center justify-between">
											<span class="text-sm font-medium">Search {i + 1}</span>
											<span class="rounded bg-muted px-2 py-0.5 text-xs">{search.search_type}</span>
										</div>
										<div class="text-sm">
											<div class="text-foreground/90">
												<span class="font-mono">"{search.query}"</span>
											</div>
											<div class="mt-1 text-muted-foreground">
												Reason: {search.reason}
											</div>
										</div>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<!-- Execution Steps -->
					<div class="rounded-lg border p-4">
						<h3 class="mb-3 font-medium">Execution Log</h3>
						<div class="space-y-3">
							{#each agentAnalysis.execution_log?.steps || [] as step}
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
											<span>{step.tokens_used} tokens</span>
											<span>{formatDuration(step.duration_ms)}</span>
										</div>
									</div>
									
									<!-- Step thought -->
									<div class="mb-2 rounded bg-muted/30 p-2">
										<p class="text-sm italic">"{step.thought}"</p>
									</div>
									
									<!-- Tool call if present -->
									{#if step.tool_call}
										<details class="text-sm">
											<summary class="cursor-pointer text-muted-foreground hover:text-foreground">
												Tool Call: {step.tool_call.tool_name}
											</summary>
											<pre class="mt-2 overflow-x-auto rounded bg-muted/20 p-2 text-xs">
{JSON.stringify(step.tool_call.parameters, null, 2)}</pre>
										</details>
									{/if}
									
									<!-- Results if present -->
									{#if step.result}
										<details class="mt-2 text-sm">
											<summary class="cursor-pointer text-muted-foreground hover:text-foreground">
												Results
											</summary>
											<pre class="mt-2 overflow-x-auto rounded bg-muted/20 p-2 text-xs">
{JSON.stringify(step.result, null, 2)}</pre>
										</details>
									{/if}
								</div>
							{/each}
						</div>
					</div>

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