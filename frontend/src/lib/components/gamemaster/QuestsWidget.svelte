<script lang="ts">
	import type { Quest, QuestObjective } from '$lib/types';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		quests: Quest[];
	}

	let { quests = [] }: Props = $props();

	let activeTab: 'active' | 'completed' | 'all' = $state('active');

	// Filtered quests based on tab
	let filteredQuests = $derived(() => {
		switch (activeTab) {
			case 'active':
				return quests.filter((q) => q.status === 'active');
			case 'completed':
				return quests.filter((q) => q.status === 'completed');
			default:
				return quests;
		}
	});

	// Get status icon and color
	function getStatusStyle(status: string): { icon: string; color: string } {
		const styles: Record<string, { icon: string; color: string }> = {
			active: { icon: '📍', color: 'text-yellow-400 border-yellow-500/30' },
			completed: { icon: '✅', color: 'text-green-400 border-green-500/30' },
			failed: { icon: '❌', color: 'text-red-400 border-red-500/30' },
			abandoned: { icon: '🚫', color: 'text-gray-400 border-gray-500/30' }
		};
		return styles[status] || styles.active;
	}

	// Calculate progress percentage
	function getQuestProgress(objectives: QuestObjective[]): number {
		if (!objectives || objectives.length === 0) return 0;
		const completed = objectives.filter((o) => o.completed).length;
		return Math.round((completed / objectives.length) * 100);
	}
</script>

{#snippet iconSnippet()}
	<svg
		xmlns="http://www.w3.org/2000/svg"
		class="h-4 w-4"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
	>
		<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
		<polyline points="14 2 14 8 20 8"></polyline>
		<line x1="16" y1="13" x2="8" y2="13"></line>
		<line x1="16" y1="17" x2="8" y2="17"></line>
	</svg>
{/snippet}

<WidgetBase title="Quests" icon={iconSnippet}>
	<!-- Tabs -->
	<div class="mb-3 flex gap-1 rounded-lg bg-gray-800 p-1">
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab === 'active'
				? 'bg-purple-500/30 text-purple-300'
				: 'text-gray-400 hover:text-gray-200'}"
			onclick={() => (activeTab = 'active')}
		>
			Active
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'completed'
				? 'bg-purple-500/30 text-purple-300'
				: 'text-gray-400 hover:text-gray-200'}"
			onclick={() => (activeTab = 'completed')}
		>
			Completed
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab === 'all'
				? 'bg-purple-500/30 text-purple-300'
				: 'text-gray-400 hover:text-gray-200'}"
			onclick={() => (activeTab = 'all')}
		>
			All
		</button>
	</div>

	<!-- Quest list -->
	<div class="max-h-64 space-y-2 overflow-y-auto">
		{#if filteredQuests().length === 0}
			<p class="py-4 text-center text-sm italic text-gray-500">No quests</p>
		{:else}
			{#each filteredQuests() as quest (quest.id)}
				{@const style = getStatusStyle(quest.status)}
				{@const progress = getQuestProgress(quest.objectives)}
				<div
					class="rounded-lg border bg-gray-800/50 p-3 transition-colors hover:bg-gray-800 {style.color}"
				>
					<!-- Title row -->
					<div class="flex items-start gap-2">
						<span class="text-sm">{style.icon}</span>
						<div class="min-w-0 flex-1">
							<h4 class="text-sm font-medium text-gray-200">{quest.title}</h4>
							{#if quest.giver}
								<p class="text-xs text-gray-500">From: {quest.giver}</p>
							{/if}
						</div>
					</div>

					<!-- Description -->
					{#if quest.description}
						<p class="mt-2 text-xs text-gray-400">{quest.description}</p>
					{/if}

					<!-- Objectives -->
					{#if quest.objectives && quest.objectives.length > 0}
						<div class="mt-2 space-y-1">
							{#each quest.objectives as objective}
								<div class="flex items-start gap-2 text-xs">
									<span class={objective.completed ? 'text-green-400' : 'text-gray-500'}>
										{objective.completed ? '✓' : '○'}
									</span>
									<span
										class={objective.completed ? 'text-gray-500 line-through' : 'text-gray-300'}
									>
										{objective.description}
									</span>
								</div>
							{/each}
						</div>

						<!-- Progress bar -->
						{#if quest.status === 'active'}
							<div class="mt-2">
								<div class="h-1.5 overflow-hidden rounded-full bg-gray-700">
									<div
										class="h-full bg-gradient-to-r from-purple-500 to-pink-500 transition-all duration-500"
										style="width: {progress}%"
									></div>
								</div>
								<p class="mt-1 text-right text-[10px] text-gray-500">{progress}% complete</p>
							</div>
						{/if}
					{/if}

					<!-- Rewards -->
					{#if quest.rewards}
						<div class="mt-2 flex items-center gap-1 text-xs text-amber-400">
							<span>🎁</span>
							<span>{quest.rewards}</span>
						</div>
					{/if}
				</div>
			{/each}
		{/if}
	</div>
</WidgetBase>
