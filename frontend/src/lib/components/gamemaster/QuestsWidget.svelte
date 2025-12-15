<script lang="ts">
	import type { Quest, QuestObjective } from '$lib/types';
	import { FileText } from 'lucide-svelte';
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
			active: { icon: '📍', color: 'text-yellow-500 border-yellow-500/30' },
			completed: { icon: '✅', color: 'text-green-500 border-green-500/30' },
			failed: { icon: '❌', color: 'text-destructive border-destructive/30' },
			abandoned: { icon: '🚫', color: 'text-muted-foreground border-border' }
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
	<FileText class="h-4 w-4" />
{/snippet}

<WidgetBase title="Quests" icon={iconSnippet}>
	<!-- Tabs -->
	<div class="bg-muted mb-3 flex gap-1 rounded-lg p-1">
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab === 'active'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'active')}
		>
			Active
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'completed'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'completed')}
		>
			Completed
		</button>
		<button
			class="flex-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab === 'all'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'all')}
		>
			All
		</button>
	</div>

	<!-- Quest list -->
	<div class="max-h-64 space-y-2 overflow-y-auto">
		{#if filteredQuests().length === 0}
			<p class="text-muted-foreground py-4 text-center text-sm italic">No quests</p>
		{:else}
			{#each filteredQuests() as quest (quest.id)}
				{@const style = getStatusStyle(quest.status)}
				{@const progress = getQuestProgress(quest.objectives)}
				<div
					class="bg-muted/50 hover:bg-muted rounded-lg border p-3 transition-colors {style.color}"
				>
					<!-- Title row -->
					<div class="flex items-start gap-2">
						<span class="text-sm">{style.icon}</span>
						<div class="min-w-0 flex-1">
							<h4 class="text-foreground text-sm font-medium">{quest.title}</h4>
							{#if quest.giver}
								<p class="text-muted-foreground text-xs">From: {quest.giver}</p>
							{/if}
						</div>
					</div>

					<!-- Description -->
					{#if quest.description}
						<p class="text-muted-foreground mt-2 text-xs">{quest.description}</p>
					{/if}

					<!-- Objectives -->
					{#if quest.objectives && quest.objectives.length > 0}
						<div class="mt-2 space-y-1">
							{#each quest.objectives as objective}
								<div class="flex items-start gap-2 text-xs">
									<span class={objective.completed ? 'text-green-500' : 'text-muted-foreground'}>
										{objective.completed ? '✓' : '○'}
									</span>
									<span
										class={objective.completed
											? 'text-muted-foreground line-through'
											: 'text-foreground'}
									>
										{objective.description}
									</span>
								</div>
							{/each}
						</div>

						<!-- Progress bar -->
						{#if quest.status === 'active'}
							<div class="mt-2">
								<div class="bg-muted h-1.5 overflow-hidden rounded-full">
									<div
										class="from-primary to-accent h-full bg-gradient-to-r transition-all duration-500"
										style="width: {progress}%"
									></div>
								</div>
								<p class="text-muted-foreground mt-1 text-right text-[10px]">
									{progress}% complete
								</p>
							</div>
						{/if}
					{/if}

					<!-- Rewards -->
					{#if quest.rewards}
						<div class="text-accent mt-2 flex items-center gap-1 text-xs">
							<span>🎁</span>
							<span>{quest.rewards}</span>
						</div>
					{/if}
				</div>
			{/each}
		{/if}
	</div>
</WidgetBase>
