<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';

	let {
		total_token_limit = $bindable(),
		recent_history_budget = $bindable(),
		rag_budget = $bindable(),
		title = 'Context Override',
		description = 'Override default context allocation for this chat.'
	} = $props<{
		total_token_limit: number;
		recent_history_budget: number;
		rag_budget: number;
		title?: string;
		description?: string;
	}>();

	// Ensure budgets don't exceed total or cause negative buffer
	$effect(() => {
		if (recent_history_budget > total_token_limit - 5000) {
			// Keep at least 5k for RAG/Buffer
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

<div class="space-y-3">
	<div>
		<h4 class="text-sm font-medium">{title}</h4>
		<p class="text-xs text-muted-foreground">{description}</p>
	</div>

	<!-- Compact Visual Budget Display -->
	<div class="space-y-1">
		<div class="flex h-3 overflow-hidden rounded-md">
			<div
				class="bg-blue-500 transition-all duration-300 ease-in-out"
				style="width: {(recent_history_budget / total_token_limit) * 100}%"
				title="Recent History: {recent_history_budget.toLocaleString()} tokens"
			></div>
			<div
				class="bg-green-500 transition-all duration-300 ease-in-out"
				style="width: {(rag_budget / total_token_limit) * 100}%"
				title="RAG: {rag_budget.toLocaleString()} tokens"
			></div>
			{#if buffer_budget > 0}
				<div
					class="bg-gray-300 dark:bg-gray-600 transition-all duration-300 ease-in-out"
					style="width: {(buffer_budget / total_token_limit) * 100}%"
					title="Buffer: {buffer_budget.toLocaleString()} tokens"
				></div>
			{/if}
		</div>
		<div class="flex justify-between text-xs text-muted-foreground">
			<span class="text-blue-600 dark:text-blue-400">Recent</span>
			<span class="text-green-600 dark:text-green-400">RAG</span>
			<span>{total_token_limit.toLocaleString()}</span>
		</div>
	</div>

	<!-- Compact Input Fields -->
	<div class="space-y-2">
		<div class="space-y-1">
			<Label for="total-context-limit-compact" class="text-xs">Total Context (tokens)</Label>
			<Input
				id="total-context-limit-compact"
				type="number"
				min={50000}
				max={2000000}
				step={10000}
				bind:value={total_token_limit}
				class="h-8 text-xs"
			/>
		</div>

		<div class="grid grid-cols-2 gap-2">
			<div class="space-y-1">
				<Label for="recent-history-budget-compact" class="text-xs">Recent</Label>
				<Input
					id="recent-history-budget-compact"
					type="number"
					min={10000}
					max={total_token_limit - 5000}
					step={5000}
					bind:value={recent_history_budget}
					class="h-8 text-xs"
				/>
			</div>

			<div class="space-y-1">
				<Label for="rag-budget-compact" class="text-xs">RAG</Label>
				<Input
					id="rag-budget-compact"
					type="number"
					min={5000}
					max={total_token_limit - recent_history_budget}
					step={5000}
					bind:value={rag_budget}
					class="h-8 text-xs"
				/>
			</div>
		</div>
	</div>

	<!-- Compact Presets -->
	<div class="space-y-1">
		<Label class="text-xs">Quick Presets</Label>
		<div class="flex gap-1">
			<Button
				variant="outline"
				size="sm"
				onclick={() => {
					total_token_limit = 200000;
					recent_history_budget = 150000;
					rag_budget = 40000;
				}}
				class="h-7 flex-1 text-xs"
			>
				200k
			</Button>
			<Button
				variant="outline"
				size="sm"
				onclick={() => {
					total_token_limit = 500000;
					recent_history_budget = 350000;
					rag_budget = 100000;
				}}
				class="h-7 flex-1 text-xs"
			>
				500k
			</Button>
			<Button
				variant="outline"
				size="sm"
				onclick={() => {
					total_token_limit = 100000;
					recent_history_budget = 75000;
					rag_budget = 15000;
				}}
				class="h-7 flex-1 text-xs"
			>
				100k
			</Button>
		</div>
	</div>

	<div class="rounded-md bg-amber-50 p-2 text-xs text-muted-foreground dark:bg-amber-950">
		<strong>⚠️</strong> Larger contexts use more resources and may increase costs.
	</div>
</div>