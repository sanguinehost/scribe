<script lang="ts">
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Card, CardHeader, CardTitle, CardContent } from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';

	import { llmStore } from '$lib/stores/llm.svelte';
	import { subscriptionStore } from '$lib/stores/subscription.svelte';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { onMount } from 'svelte';

	let {
		total_token_limit = $bindable(),
		recent_history_budget = $bindable(),
		rag_budget = $bindable(),
		rag_chronicles_limit = $bindable(),
		rag_lorebooks_limit = $bindable(),
		rag_older_chat_limit = $bindable(),
		title = 'Context Window Management',
		description = 'Configure token allocation for context processing.',
		selectedModelId = undefined
	} = $props<{
		total_token_limit: number;
		recent_history_budget: number;
		rag_budget: number;
		rag_chronicles_limit: number;
		rag_lorebooks_limit: number;
		rag_older_chat_limit: number;
		title?: string;
		description?: string;
		selectedModelId?: string;
	}>();

	// Get dynamic max context size based on selected model
	const maxContextSize = $derived(() => {
		if (selectedModelId) {
			const maxSize = llmStore.getMaxContextSize(selectedModelId);
			if (maxSize) return maxSize;
		}
		// Fallback to conservative default
		return 200000;
	});

	// Get subscription tier limit (if payment feature is enabled)
	const subscriptionLimit = $derived(() => {
		if (ENABLE_PAYMENTS && subscriptionStore.planFeatures?.max_context_tokens) {
			return subscriptionStore.planFeatures.max_context_tokens;
		}
		return null;
	});

	// Calculate max allowed tokens (model limit, subscription tier limit, or conservative default)
	const max_allowed = $derived(() => {
		const modelMax = maxContextSize();
		const tierLimit = subscriptionLimit();

		// If we have a subscription tier limit, use the minimum of model max and tier limit
		if (tierLimit !== null) {
			return Math.min(total_token_limit, modelMax, tierLimit);
		}

		// Otherwise just use model max
		return Math.min(total_token_limit, modelMax);
	});

	// Check if user is hitting their subscription tier limit
	const isAtTierLimit = $derived(() => {
		const tierLimit = subscriptionLimit();
		return tierLimit !== null && total_token_limit >= tierLimit;
	});

	// Load model capabilities on mount
	onMount(() => {
		llmStore.fetchModels();
	});

	// Constraint validation - only runs when dependencies change
	$effect(() => {
		const maxAllowed = max_allowed();

		// Clamp recent history budget
		if (recent_history_budget > maxAllowed) {
			recent_history_budget = maxAllowed;
		}

		// Clamp RAG budget to remaining space
		if (rag_budget > maxAllowed - recent_history_budget) {
			rag_budget = maxAllowed - recent_history_budget;
		}

		// Ensure minimum budgets
		if (recent_history_budget < 1000) {
			recent_history_budget = 1000;
		}
		if (rag_budget < 500) {
			rag_budget = 500;
		}

		// Ensure granular RAG limits don't exceed RAG budget
		// If they are 0, it means no limit (or system default), but here we treat them as individual caps
		// We don't strictly enforce sum(granular) <= rag_budget because rag_budget is the total cap
		// and granular limits are per-category caps.

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
			rag: Math.floor(total * rag_ratio),
			chronicles: Math.floor(total * rag_ratio * 0.4),
			lorebooks: Math.floor(total * rag_ratio * 0.4),
			older_chats: Math.floor(total * rag_ratio * 0.2)
		};
	}

	// Apply a preset value to all budget settings
	function applyPreset(_value: number) {
		total_token_limit = _value;
		const budgets = calculatePresetBudgets(_value);
		recent_history_budget = budgets.history;
		rag_budget = budgets.rag;
		rag_chronicles_limit = budgets.chronicles;
		rag_lorebooks_limit = budgets.lorebooks;
		rag_older_chat_limit = budgets.older_chats;
	}

	// Generate dynamic preset buttons based on model capabilities and subscription tier
	const presetButtons = $derived(() => {
		const modelMax = maxContextSize();
		const tierLimit = subscriptionLimit();
		const presets = [4000, 8000, 16000, 32000, 64000, 128000, 200000, 1000000];

		// Determine effective maximum (considering both model and subscription limits)
		const effectiveMax = tierLimit !== null ? Math.min(modelMax, tierLimit) : modelMax;

		// Filter presets to only show those within effective capabilities
		return presets
			.filter((preset) => preset <= effectiveMax)
			.map((preset) => ({
				value: preset,
				label: preset >= 1000000 ? `${preset / 1000000}M` : `${preset / 1000}K`,
				title: getPresetTitle(preset)
			}));
	});

	function getPresetTitle(preset: number): string {
		const titleMap: Record<number, string> = {
			4000: 'Ultra-low cost, minimal context',
			8000: 'Low cost, basic conversations',
			16000: 'Budget-friendly, moderate context',
			32000: 'Balanced cost/performance',
			64000: 'Good for medium conversations',
			128000: 'Large context for complex tasks',
			200000: 'Optimal balance (many models)',
			1000000: 'Maximum context (expensive)'
		};
		return titleMap[preset] || 'Custom context size';
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
						{#each presetButtons() as preset}
							<ButtonComponent
								variant="ghost"
								size="sm"
								class="h-6 px-2 text-xs"
								title={preset.title}
								onclick={() => applyPreset(preset.value)}
							>
								{preset.label}
							</ButtonComponent>
						{/each}
					</div>
				</div>
				<Input
					id="total-context-limit"
					type="number"
					min={4000}
					max={subscriptionLimit() ?? maxContextSize()}
					step={1000}
					bind:value={total_token_limit}
				/>
				<p class="text-xs text-muted-foreground">
					Maximum tokens the model can process. Higher = more context but slower/costlier.
					{#if selectedModelId}
						{@const capabilities = llmStore.getModelCapabilities(selectedModelId)}
						{#if capabilities}
							<br />Current model: {capabilities.context_window_size.toLocaleString()} tokens max
						{/if}
					{/if}
					{#if ENABLE_PAYMENTS && subscriptionLimit()}
						<br /><strong>Your plan limit: {subscriptionLimit()?.toLocaleString()} tokens</strong>
						{#if isAtTierLimit()}
							<span class="text-amber-600 dark:text-amber-400"> (at plan maximum) </span>
						{/if}
					{/if}
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

			<div class="space-y-3 rounded-md border border-dashed p-3">
				<div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
					Granular RAG Limits (within RAG budget)
				</div>
				<div class="grid grid-cols-3 gap-3">
					<div class="space-y-1">
						<Label for="rag-chronicles-limit" class="text-xs">Chronicles</Label>
						<Input
							id="rag-chronicles-limit"
							type="number"
							min={0}
							max={rag_budget}
							step={100}
							bind:value={rag_chronicles_limit}
							class="h-8 text-xs"
						/>
					</div>
					<div class="space-y-1">
						<Label for="rag-lorebooks-limit" class="text-xs">Lorebooks</Label>
						<Input
							id="rag-lorebooks-limit"
							type="number"
							min={0}
							max={rag_budget}
							step={100}
							bind:value={rag_lorebooks_limit}
							class="h-8 text-xs"
						/>
					</div>
					<div class="space-y-1">
						<Label for="rag-older-chat-limit" class="text-xs">Older Chats</Label>
						<Input
							id="rag-older-chat-limit"
							type="number"
							min={0}
							max={rag_budget}
							step={100}
							bind:value={rag_older_chat_limit}
							class="h-8 text-xs"
						/>
					</div>
				</div>
				<p class="text-[10px] italic text-muted-foreground">
					Individual caps for each category. Items are still subject to the total RAG budget above.
				</p>
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
				{#snippet presetButtonsUI()}
					{@const tierLimit = subscriptionLimit()}
					{@const effectiveMax = tierLimit ?? maxContextSize()}

					<!-- Efficient preset (64k) -->
					{#if 64000 <= effectiveMax}
						<ButtonComponent
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
						</ButtonComponent>
					{/if}

					<!-- Balanced preset (200k) -->
					{#if 200000 <= effectiveMax}
						<ButtonComponent
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
						</ButtonComponent>
					{/if}

					<!-- Large preset (400k) - only if tier allows -->
					{#if 400000 <= effectiveMax}
						<ButtonComponent
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
						</ButtonComponent>
					{/if}
				{/snippet}
				<div class="grid grid-cols-3 gap-2">
					{@render presetButtonsUI()}
				</div>
			</div>

			<div class="space-y-2">
				<div class="rounded-lg bg-blue-50 p-3 text-xs text-muted-foreground dark:bg-blue-950">
					<strong>🧠 Strategic Memory Management:</strong> The system uses advanced middle-out truncation
					to preserve the most important context (system prompts + recent 8 messages) while intelligently
					managing older conversation history. This ensures optimal narrative continuity and cost efficiency.
				</div>
				{#if ENABLE_PAYMENTS && isAtTierLimit()}
					<div class="rounded-lg bg-purple-50 p-3 text-xs dark:bg-purple-950">
						<strong>📊 Subscription Limit:</strong>
						<span class="text-muted-foreground">
							You're using the maximum context size for your
							<strong class="text-foreground">{subscriptionStore.getPlanDisplayName()}</strong> plan
							({subscriptionLimit()?.toLocaleString()} tokens). Upgrade to access larger context windows.
						</span>
					</div>
				{/if}
				<div class="rounded-lg bg-amber-50 p-3 text-xs text-muted-foreground dark:bg-amber-950">
					<strong>⚠️ Note:</strong> Larger contexts use more resources and increase costs. Settings are
					conservative to ensure the backend's hard token limits are respected during strategic processing.
				</div>
			</div>
		</div>
	</CardContent>
</Card>
