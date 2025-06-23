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

	// Ensure budgets don't exceed total or cause negative buffer
	$effect(() => {
		// Calculate minimum buffer based on context size (larger contexts get bigger buffers)
		const min_buffer = Math.min(Math.max(Math.floor(total_token_limit * 0.05), 500), 5000);
		const min_history = Math.min(Math.max(Math.floor(total_token_limit * 0.2), 1000), 10000);
		const min_rag = Math.min(Math.max(Math.floor(total_token_limit * 0.1), 500), 5000);

		// Ensure history budget doesn't leave too little for RAG
		if (recent_history_budget > total_token_limit - min_buffer) {
			recent_history_budget = total_token_limit - min_buffer;
		}
		
		// Ensure RAG budget fits within remaining space
		if (rag_budget > total_token_limit - recent_history_budget) {
			rag_budget = total_token_limit - recent_history_budget;
		}
		
		// Set reasonable minimums based on context size
		if (recent_history_budget < min_history && total_token_limit >= min_history + min_rag + min_buffer) {
			recent_history_budget = min_history;
		}
		if (rag_budget < min_rag && total_token_limit >= min_history + min_rag + min_buffer) {
			rag_budget = min_rag;
		}

		// Prevent total from being less than sum of parts
		const required_total = recent_history_budget + rag_budget + min_buffer;
		if (total_token_limit < required_total) {
			total_token_limit = required_total;
		}
	});

	const buffer_budget = $derived(total_token_limit - recent_history_budget - rag_budget);
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
							onclick={() => { total_token_limit = 4096; }}
						>
							4K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Low cost, basic conversations"
							onclick={() => { total_token_limit = 8192; }}
						>
							8K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Budget-friendly, moderate context"
							onclick={() => { total_token_limit = 16384; }}
						>
							16K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Balanced cost/performance"
							onclick={() => { total_token_limit = 32768; }}
						>
							32K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Good for medium conversations"
							onclick={() => { total_token_limit = 65536; }}
						>
							64K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Large context for complex tasks"
							onclick={() => { total_token_limit = 131072; }}
						>
							128K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Gemini cost threshold (optimal)"
							onclick={() => { total_token_limit = 200000; }}
						>
							200K
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-6 px-2 text-xs"
							title="Maximum context (expensive)"
							onclick={() => { total_token_limit = 1000000; }}
						>
							1M
						</Button>
					</div>
				</div>
				<Input
					id="total-context-limit"
					type="number"
					min={4096}
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
							total_token_limit = 200000;
							recent_history_budget = 150000;
							rag_budget = 40000; // Adjusted to leave 10k buffer
						}}
					>
						Balanced<br />
						<span class="text-xs text-muted-foreground">200k total</span>
					</Button>
					<Button
						variant="outline"
						size="sm"
						onclick={() => {
							total_token_limit = 500000;
							recent_history_budget = 350000;
							rag_budget = 100000; // Adjusted to leave 50k buffer
						}}
					>
						Large<br />
						<span class="text-xs text-muted-foreground">500k total</span>
					</Button>
					<Button
						variant="outline"
						size="sm"
						onclick={() => {
							total_token_limit = 100000;
							recent_history_budget = 75000; // Adjusted
							rag_budget = 15000; // Adjusted to leave 10k buffer
						}}
					>
						Efficient<br />
						<span class="text-xs text-muted-foreground">100k total</span>
					</Button>
				</div>
			</div>

			<div class="rounded-lg bg-amber-50 p-3 text-xs text-muted-foreground dark:bg-amber-950">
				<strong>⚠️ Note:</strong> Larger context windows use more computational resources and may increase
				response time and costs. The system automatically manages token allocation within your specified
				limits.
			</div>
		</div>
	</CardContent>
</Card>
