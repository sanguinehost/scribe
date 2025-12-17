<script lang="ts">
	import type { Quest, QuestObjective } from '$lib/types';
	import { FileText, Star, ListTodo } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		quests: Quest[];
	}

	let { quests = [] }: Props = $props();

	let activeTab: 'main' | 'optional' | 'all' = $state('main');

	// Separate main and optional quests
	const mainQuests = $derived(quests.filter((q) => q.is_main));
	const optionalQuests = $derived(quests.filter((q) => !q.is_main));

	// Filtered quests based on tab
	const filteredQuests = $derived(() => {
		switch (activeTab) {
			case 'main':
				return mainQuests.filter((q) => q.status === 'active');
			case 'optional':
				return optionalQuests.filter((q) => q.status === 'active');
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

{#snippet questCard(quest: Quest)}
	{@const style = getStatusStyle(quest.status)}
	{@const progress = getQuestProgress(quest.objectives)}
	<div class="rounded-lg border bg-muted/50 p-3 transition-colors hover:bg-muted {style.color}">
		<!-- Title row -->
		<div class="flex items-start gap-2">
			<span class="text-sm">{style.icon}</span>
			<div class="min-w-0 flex-1">
				<div class="flex items-center gap-2">
					<h4 class="text-sm font-medium text-foreground">{quest.title}</h4>
					{#if quest.is_main}
						<span class="rounded bg-yellow-500/20 px-1 text-[10px] text-yellow-500">Main</span>
					{/if}
				</div>
				{#if quest.giver}
					<p class="text-xs text-muted-foreground">From: {quest.giver}</p>
				{/if}
			</div>
		</div>

		<!-- Description -->
		{#if quest.description}
			<p class="mt-2 text-xs text-muted-foreground">{quest.description}</p>
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
							class={objective.completed ? 'text-muted-foreground line-through' : 'text-foreground'}
						>
							{objective.description}
						</span>
					</div>
				{/each}
			</div>

			<!-- Progress bar -->
			{#if quest.status === 'active'}
				<div class="mt-2">
					<div class="h-1.5 overflow-hidden rounded-full bg-muted">
						<div
							class="h-full bg-gradient-to-r from-primary to-accent transition-all duration-500"
							style="width: {progress}%"
						></div>
					</div>
					<p class="mt-1 text-right text-[10px] text-muted-foreground">{progress}% complete</p>
				</div>
			{/if}
		{/if}

		<!-- Rewards -->
		{#if quest.rewards}
			<div class="mt-2 flex items-center gap-1 text-xs text-accent">
				<span>🎁</span>
				<span>{quest.rewards}</span>
			</div>
		{/if}
	</div>
{/snippet}

<WidgetBase title="Quests" icon={iconSnippet}>
	<!-- Tabs: Main / Optional / All -->
	<div class="mb-3 flex gap-1 rounded-lg bg-muted p-1">
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'main'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'main')}
		>
			<Star class="h-3 w-3" />
			Main ({mainQuests.filter((q) => q.status === 'active').length})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'optional'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'optional')}
		>
			<ListTodo class="h-3 w-3" />
			Optional ({optionalQuests.filter((q) => q.status === 'active').length})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'all'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'all')}
		>
			All ({quests.length})
		</button>
	</div>

	<!-- Quest list -->
	<div class="max-h-64 space-y-2 overflow-y-auto">
		{#if filteredQuests().length === 0}
			<p class="py-4 text-center text-sm italic text-muted-foreground">
				{#if activeTab === 'main'}
					No active main quest
				{:else if activeTab === 'optional'}
					No optional quests
				{:else}
					No quests
				{/if}
			</p>
		{:else}
			{#each filteredQuests() as quest (quest.id)}
				{@render questCard(quest)}
			{/each}
		{/if}
	</div>
</WidgetBase>
