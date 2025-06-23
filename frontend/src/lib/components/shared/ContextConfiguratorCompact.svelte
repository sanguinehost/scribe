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

	// Strategic token allocation with conservative limits to account for backend enforcement
	$effect(() => {
		// More conservative buffer calculations to account for strategic truncation overhead
		// Backend uses middle-out truncation and preserves 8 messages by default
		const min_buffer = Math.min(Math.max(Math.floor(total_token_limit * 0.08), 1000), 8000);
		const min_history = Math.min(Math.max(Math.floor(total_token_limit * 0.25), 2000), 15000);
		const min_rag = Math.min(Math.max(Math.floor(total_token_limit * 0.15), 1000), 8000);

		// Conservative validation: ensure budgets leave adequate buffer for strategic processing
		if (recent_history_budget > total_token_limit - min_buffer - 1000) {
			recent_history_budget = total_token_limit - min_buffer - 1000;
		}

		// Ensure RAG budget accounts for potential compression overhead
		if (rag_budget > total_token_limit - recent_history_budget - min_buffer) {
			rag_budget = total_token_limit - recent_history_budget - min_buffer;
		}

		// Set conservative minimums that work well with strategic truncation
		if (
			recent_history_budget < min_history &&
			total_token_limit >= min_history + min_rag + min_buffer
		) {
			recent_history_budget = min_history;
		}
		if (rag_budget < min_rag && total_token_limit >= min_history + min_rag + min_buffer) {
			rag_budget = min_rag;
		}

		// Prevent total from being less than sum of parts (with extra safety margin)
		const required_total = recent_history_budget + rag_budget + min_buffer + 500;
		if (total_token_limit < required_total) {
			total_token_limit = required_total;
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
							total_token_limit = 8192;
						}}
					>
						8K
					</Button>
					<Button
						variant="ghost"
						size="sm"
						class="h-5 px-1 text-xs"
						onclick={() => {
							total_token_limit = 32768;
						}}
					>
						32K
					</Button>
					<Button
						variant="ghost"
						size="sm"
						class="h-5 px-1 text-xs"
						onclick={() => {
							total_token_limit = 131072;
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
						}}
					>
						200K
					</Button>
				</div>
			</div>
			<Input
				id="total-context-limit-compact"
				type="number"
				min={4096}
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
					recent_history_budget = 120000;
					rag_budget = 60000;
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
					recent_history_budget = 300000;
					rag_budget = 150000;
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
					rag_budget = 25000;
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
