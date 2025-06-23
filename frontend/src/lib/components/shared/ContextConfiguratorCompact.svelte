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
		if (total <= 8192) {
			// Small context: prioritize recent history
			history_ratio = 0.7;
			rag_ratio = 0.25;
		} else if (total <= 32768) {
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
					class="bg-gray-300 transition-all duration-300 ease-in-out dark:bg-gray-600"
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
			<div class="flex items-center justify-between">
				<Label for="total-context-limit-compact" class="text-xs">Total Context (tokens)</Label>
				<div class="flex gap-1">
					<Button
						variant="ghost"
						size="sm"
						class="h-5 px-1 text-xs"
						onclick={() => {
							total_token_limit = 4096;
							const budgets = calculatePresetBudgets(4096);
							recent_history_budget = budgets.history;
							rag_budget = budgets.rag;
						}}
					>
						4K
					</Button>
					<Button
						variant="ghost"
						size="sm"
						class="h-5 px-1 text-xs"
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
						class="h-5 px-1 text-xs"
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
						class="h-5 px-1 text-xs"
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
						class="h-5 px-1 text-xs"
						onclick={() => {
							total_token_limit = 200000;
							const budgets = calculatePresetBudgets(200000);
							recent_history_budget = budgets.history;
							rag_budget = budgets.rag;
						}}
					>
						200K
					</Button>
				</div>
			</div>
			<Input
				id="total-context-limit-compact"
				type="number"
				min={4000}
				max={2000000}
				step={1000}
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
					min={1000}
					max={total_token_limit - 500}
					step={1000}
					bind:value={recent_history_budget}
					class="h-8 text-xs"
				/>
			</div>

			<div class="space-y-1">
				<Label for="rag-budget-compact" class="text-xs">RAG</Label>
				<Input
					id="rag-budget-compact"
					type="number"
					min={500}
					max={total_token_limit - recent_history_budget}
					step={500}
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
					recent_history_budget = 110000;
					rag_budget = 80000;
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
					recent_history_budget = 275000;
					rag_budget = 200000;
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
					recent_history_budget = 60000;
					rag_budget = 35000;
				}}
				class="h-7 flex-1 text-xs"
			>
				100k
			</Button>
		</div>
	</div>

	<div class="space-y-1">
		<div class="rounded-md bg-blue-50 p-2 text-xs text-muted-foreground dark:bg-blue-950">
			<strong>🧠</strong> Strategic memory: preserves key context with middle-out truncation.
		</div>
		<div class="rounded-md bg-amber-50 p-2 text-xs text-muted-foreground dark:bg-amber-950">
			<strong>⚠️</strong> Larger contexts use more resources and may increase costs.
		</div>
	</div>
</div>
