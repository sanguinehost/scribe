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
		if (recent_history_budget > total_token_limit - 5000) { // Keep at least 5k for RAG/Buffer
			recent_history_budget = total_token_limit - 5000;
		}
		if (rag_budget > total_token_limit - recent_history_budget) {
			rag_budget = total_token_limit - recent_history_budget;
		}
		if (recent_history_budget < 10000 && total_token_limit >= 20000) recent_history_budget = 10000;
		if (rag_budget < 5000 && total_token_limit >= 15000) rag_budget = 5000;

        // Prevent total from being less than sum of parts if parts are reduced first
        if (total_token_limit < recent_history_budget + rag_budget) {
            total_token_limit = recent_history_budget + rag_budget + 10000; // Add a small buffer
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
				<Label for="total-context-limit">Total Context Window (tokens)</Label>
				<Input
					id="total-context-limit"
					type="number"
					min={50000}
					max={2000000}
					step={10000}
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
						min={10000}
						max={total_token_limit - 5000}
						step={5000}
						bind:value={recent_history_budget}
					/>
					<p class="text-xs text-muted-foreground">
						Tokens for recent chat messages
					</p>
				</div>
				
				<div class="space-y-2">
					<Label for="rag-budget">RAG Context Budget</Label>
					<Input
						id="rag-budget"
						type="number"
						min={5000}
						max={total_token_limit - recent_history_budget}
						step={5000}
						bind:value={rag_budget}
					/>
					<p class="text-xs text-muted-foreground">
						Tokens for lorebooks + older messages
					</p>
				</div>
			</div>

			<!-- Visual Budget Breakdown -->
			<div class="space-y-2">
				<div class="text-sm font-medium">Budget Allocation</div>
				<div class="w-full bg-muted rounded-lg p-3">
					<div class="flex h-6 rounded-lg overflow-hidden">
						<div 
							class="bg-blue-500 flex items-center justify-center text-white text-xs font-medium transition-all duration-300 ease-in-out"
							style="width: {(recent_history_budget / total_token_limit) * 100}%"
							title="Recent History: {recent_history_budget.toLocaleString()} tokens"
						>
							Recent
						</div>
						<div 
							class="bg-green-500 flex items-center justify-center text-white text-xs font-medium transition-all duration-300 ease-in-out"
							style="width: {(rag_budget / total_token_limit) * 100}%"
							title="RAG: {rag_budget.toLocaleString()} tokens"
						>
							RAG
						</div>
						{#if buffer_budget > 0}
						<div 
							class="bg-gray-300 dark:bg-gray-600 flex items-center justify-center text-gray-700 dark:text-gray-200 text-xs font-medium transition-all duration-300 ease-in-out"
							style="width: {(buffer_budget / total_token_limit) * 100}%"
							title="Buffer: {buffer_budget.toLocaleString()} tokens"
						>
							Buffer
						</div>
						{/if}
					</div>
					<div class="flex justify-between text-xs text-muted-foreground mt-2">
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
						Balanced<br/>
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
						Large<br/>
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
						Efficient<br/>
						<span class="text-xs text-muted-foreground">100k total</span>
					</Button>
				</div>
			</div>

			<div class="text-xs text-muted-foreground p-3 bg-amber-50 dark:bg-amber-950 rounded-lg">
				<strong>⚠️ Note:</strong> Larger context windows use more computational resources and may increase response time and costs. The system automatically manages token allocation within your specified limits.
			</div>
		</div>
	</CardContent>
</Card>