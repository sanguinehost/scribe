<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';

	let {
		total_token_limit = $bindable(),
		recent_history_budget = $bindable(),
		rag_budget = $bindable(),
		title = 'Context Window Management',
		description = 'Configure token allocation for context processing.'
	} = $props<{
		total_token_limit: number;
		recent_history_budget: number;
		rag_budget: number;
		title?: string;
		description?: string;
	}>();

	// Constraint validation
	$effect(() => {
		// Ensure budgets don't exceed total
		const max_allowed = total_token_limit;

		// Clamp recent history budget
		if (recent_history_budget > max_allowed) {
			recent_history_budget = max_allowed;
		}

		// Clamp RAG budget to remaining space
		if (rag_budget > max_allowed - recent_history_budget) {
			rag_budget = max_allowed - recent_history_budget;
		}

		// Ensure minimum budgets
		if (recent_history_budget < 1000) {
			recent_history_budget = 1000;
		}
		if (rag_budget < 500) {
			rag_budget = 500;
		}

		// Ensure total is at least the sum of the two budgets
		const min_total = recent_history_budget + rag_budget;
		if (total_token_limit < min_total) {
			total_token_limit = min_total;
		}
	});

	const buffer_budget = $derived(
		Math.max(0, total_token_limit - recent_history_budget - rag_budget)
	);

	// Smart preset calculation based on total tokens
	function calculatePresetBudgets(total: number) {
		// Backend defaults suggest 75% for recent history, 20% for RAG, 5% buffer
		// But we'll use more balanced allocations
		let history_ratio = 0.75;
		let rag_ratio = 0.2;

		// Adjust ratios based on context size
		if (total <= 8000) {
			// Small context: prioritize recent history
			history_ratio = 0.7;
			rag_ratio = 0.25;
		} else if (total <= 32000) {
			// Medium context: balanced
			history_ratio = 0.65;
			rag_ratio = 0.3;
		} else if (total <= 128000) {
			// Large context: more RAG
			history_ratio = 0.6;
			rag_ratio = 0.35;
		} else {
			// Very large context: even more RAG
			history_ratio = 0.55;
			rag_ratio = 0.4;
		}

		return {
			history: Math.floor(total * history_ratio),
			rag: Math.floor(total * rag_ratio)
		};
	}
</script>

<Card>
	<CardHeader>
		<CardTitle class="text-lg">{title}</CardTitle>
		<p class="text-sm text-muted-foreground">{description}</p>
	</CardHeader>
	<CardContent class="space-y-4">
		<div class="space-y-4">
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<Label for="total-context-limit">Total Context Window (tokens)</Label>
					<div class="flex flex-wrap gap-1">
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Ultra-low cost, minimal context"
							onclick={() => {
								total_token_limit = 4000;
								const budgets = calculatePresetBudgets(4000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							4K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Low cost, basic conversations"
							onclick={() => {
								total_token_limit = 8000;
								const budgets = calculatePresetBudgets(8000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							8K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Budget-friendly, moderate context"
							onclick={() => {
								total_token_limit = 16000;
								const budgets = calculatePresetBudgets(16000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							16K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Balanced cost/performance"
							onclick={() => {
								total_token_limit = 32000;
								const budgets = calculatePresetBudgets(32000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							32K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Good for medium conversations"
							onclick={() => {
								total_token_limit = 64000;
								const budgets = calculatePresetBudgets(64000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							64K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Large context for complex tasks"
							onclick={() => {
								total_token_limit = 128000;
								const budgets = calculatePresetBudgets(128000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							128K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Gemini cost threshold (optimal)"
							onclick={() => {
								total_token_limit = 200000;
								const budgets = calculatePresetBudgets(200000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							200K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Maximum context (expensive)"
							onclick={() => {
								total_token_limit = 1000000;
								const budgets = calculatePresetBudgets(1000000);
								recent_history_budget = budgets.history;
								rag_budget = budgets.rag;
							}}
						>
							1M
						</Button>
					</div>
				</div>
				<Input
					id="total-context-limit"
					type="number"
					min={4000}
					max={2000000}
					step={1000}
					bind:value={total_token_limit}
				/>
				<p class="text-xs text-muted-foreground">
					Maximum tokens the model can process. Higher = more context but slower/costlier.
				</p>
			</div>

			<div class="grid grid-cols-2 gap-4">
				<div class="space-y-2">
					<Label for="recent-history-budget">Recent History Budget</Label>
					<Input
						id="recent-history-budget"
						type="number"
						min={1000}
						max={total_token_limit - 1000}
						step={500}
						bind:value={recent_history_budget}
					/>
					<p class="text-xs text-muted-foreground">Tokens for recent chat messages</p>
				</div>

				<div class="space-y-2">
					<Label for="rag-budget">RAG Context Budget</Label>
					<Input
						id="rag-budget"
						type="number"
						min={500}
						max={total_token_limit - recent_history_budget}
						step={500}
						bind:value={rag_budget}
					/>
					<p class="text-xs text-muted-foreground">Tokens for lorebooks + older messages</p>
				</div>
			</div>

			<!-- Visual Budget Breakdown -->
			<div class="space-y-2">
				<div class="text-sm font-medium">Budget Allocation</div>
				<div class="w-full rounded-lg bg-muted p-3">
					<div class="flex h-6 overflow-hidden rounded-lg">
						<div
							class="flex items-center justify-center bg-blue-500 text-xs font-medium text-white transition-all duration-300 ease-in-out"
							style="width: {(recent_history_budget / total_token_limit) * 100}%"
							title="Recent History: {recent_history_budget.toLocaleString()} tokens"
						>
							Recent
						</div>
						<div
							class="flex items-center justify-center bg-green-500 text-xs font-medium text-white transition-all duration-300 ease-in-out"
							style="width: {(rag_budget / total_token_limit) * 100}%"
							title="RAG: {rag_budget.toLocaleString()} tokens"
						>
							RAG
						</div>
						{#if buffer_budget > 0}
							<div
								class="flex items-center justify-center bg-gray-300 text-xs font-medium text-gray-700 transition-all duration-300 ease-in-out dark:bg-gray-600 dark:text-gray-200"
								style="width: {(buffer_budget / total_token_limit) * 100}%"
								title="Buffer: {buffer_budget.toLocaleString()} tokens"
							>
								Buffer
							</div>
						{/if}
					</div>
					<div class="mt-2 flex justify-between text-xs text-muted-foreground">
						<span>Recent: {recent_history_budget.toLocaleString()}</span>
						<span>RAG: {rag_budget.toLocaleString()}</span>
						<span>Total: {total_token_limit.toLocaleString()}</span>
					</div>
				</div>
			</div>

			<!-- Presets -->
			<div class="space-y-2">
				<Label>Quick Presets</Label>
				<div class="grid grid-cols-3 gap-2">
					<Button
						variant="outline"
						size="sm"
						onclick={() => {
							total_token_limit = 64000;
							recent_history_budget = 40000;
							rag_budget = 20000; // Budget-friendly
						}}
					>
						Efficient<br />
						<span class="text-xs text-muted-foreground">64k total</span>
					</Button>
					<Button
						variant="outline"
						size="sm"
						onclick={() => {
							total_token_limit = 200000;
							recent_history_budget = 120000;
							rag_budget = 70000; // Cost-effective maximum
						}}
					>
						Balanced<br />
						<span class="text-xs text-muted-foreground">200k total</span>
					</Button>
					<Button
						variant="outline"
						size="sm"
						onclick={() => {
							total_token_limit = 400000;
							recent_history_budget = 240000;
							rag_budget = 140000; // High cost, complex tasks
						}}
					>
						Large<br />
						<span class="text-xs text-muted-foreground">400k total</span>
					</Button>
				</div>
			</div>

			<div class="space-y-2">
				<div class="rounded-lg bg-blue-50 p-3 text-xs text-muted-foreground dark:bg-blue-950">
					<strong>🧠 Strategic Memory Management:</strong> The system uses advanced middle-out truncation
					to preserve the most important context (system prompts + recent 8 messages) while intelligently
					managing older conversation history. This ensures optimal narrative continuity and cost efficiency.
				</div>
				<div class="rounded-lg bg-amber-50 p-3 text-xs text-muted-foreground dark:bg-amber-950">
					<strong>⚠️ Note:</strong> Larger contexts use more resources and increase costs. Settings are
					conservative to ensure the backend's hard token limits are respected during strategic processing.
				</div>
			</div>
		</div>
	</CardContent>
</Card>
