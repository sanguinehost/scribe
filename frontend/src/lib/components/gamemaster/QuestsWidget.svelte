<script lang="ts">
	import type { Quest, GameState } from '$lib/types';
	import { Scroll, CheckCircle2, Circle, Edit2, Save, X, Plus, Trash2 } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';
	import { Textarea } from '../ui/textarea';
	import { Label } from '../ui/label';

	interface Props {
		quests?: Quest[] | null;
		onUpdate?: (updates: Partial<GameState>) => void;
	}

	let { quests = [], onUpdate }: Props = $props();

	// Ensure we always have an array
	const questList = $derived(quests ?? []);

	let activeTab: 'active' | 'completed' = $state('active');

	let isEditing = $state(false);
	let editQuests = $state<Quest[]>([]);

	function startEditing() {
		editQuests = quests ? JSON.parse(JSON.stringify(quests)) : [];
		isEditing = true;
	}

	function save() {
		if (onUpdate) {
			onUpdate({ quests: editQuests });
		}
		isEditing = false;
	}

	function cancel() {
		isEditing = false;
	}

	function addQuest() {
		const newQuest: Quest = {
			id: crypto.randomUUID(),
			title: 'New Quest',
			description: '',
			status: activeTab === 'active' ? 'active' : 'completed',
			objectives: [],
			is_main: false,
			giver: '',
			rewards: ''
		};
		editQuests.push(newQuest);
	}

	function removeQuest(index: number) {
		editQuests = editQuests.filter((_, i) => i !== index);
	}

	function addObjective(questIndex: number) {
		if (!editQuests[questIndex].objectives) editQuests[questIndex].objectives = [];
		editQuests[questIndex].objectives.push({
			description: 'New Objective',
			completed: false,
			progress: '0'
		});
	}

	function removeObjective(questIndex: number, objIndex: number) {
		if (editQuests[questIndex].objectives) {
			editQuests[questIndex].objectives = editQuests[questIndex].objectives.filter(
				(_, i) => i !== objIndex
			);
		}
	}

	// Filter quests based on status
	const activeQuests = $derived(questList.filter((q) => q.status === 'active'));
	const completedQuests = $derived(
		questList.filter((q) => q.status === 'completed' || q.status === 'failed')
	);

	const editActiveQuests = $derived(editQuests.filter((q) => q.status === 'active'));
	const editCompletedQuests = $derived(
		editQuests.filter((q) => q.status === 'completed' || q.status === 'failed')
	);
</script>

{#snippet iconSnippet()}
	<Scroll class="h-4 w-4" />
{/snippet}

{#snippet questCard(quest: Quest)}
	<div class="rounded-lg border border-border bg-muted/50 p-3">
		<div class="mb-2 flex items-start justify-between gap-2">
			<h4 class="font-medium text-foreground">{quest.title}</h4>
			<span
				class="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider {quest.status === 'active'
					? 'bg-primary/20 text-primary'
					: quest.status === 'completed'
						? 'bg-green-500/20 text-green-500'
						: 'bg-destructive/20 text-destructive'}"
			>
				{quest.status}
			</span>
		</div>
		<p class="mb-3 text-xs text-muted-foreground">{quest.description}</p>

		{#if quest.objectives && quest.objectives.length > 0}
			<div class="space-y-1.5">
				{#each quest.objectives as objective, i (i)}
					<div class="flex items-start gap-2 text-xs">
						{#if objective.completed}
							<CheckCircle2 class="mt-0.5 h-3.5 w-3.5 shrink-0 text-green-500" />
							<span class="text-muted-foreground line-through">{objective.description}</span>
						{:else}
							<Circle class="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
							<span class="text-foreground">{objective.description}</span>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	</div>
{/snippet}

{#snippet editQuestCard(quest: Quest, index: number)}
	<div class="space-y-3 rounded-lg border border-border bg-muted/30 p-3">
		<div class="flex items-center gap-2">
			<Input
				bind:value={quest.title}
				class="h-7 flex-1 text-xs font-medium"
				placeholder="Quest Title"
			/>
			<select
				bind:value={quest.status}
				class="h-7 rounded-md border border-input bg-background px-2 py-1 text-xs ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
			>
				<option value="active">Active</option>
				<option value="completed">Completed</option>
				<option value="failed">Failed</option>
			</select>
			<Button
				variant="ghost"
				size="icon"
				class="h-7 w-7 text-destructive"
				onclick={() => removeQuest(index)}
			>
				<Trash2 class="h-3.5 w-3.5" />
			</Button>
		</div>

		<Textarea
			bind:value={quest.description}
			class="min-h-[60px] text-xs"
			placeholder="Description"
		/>

		<div class="space-y-2">
			<div class="flex items-center justify-between">
				<Label class="text-[10px] text-muted-foreground">Objectives</Label>
				<Button variant="ghost" size="icon" class="h-5 w-5" onclick={() => addObjective(index)}>
					<Plus class="h-3 w-3" />
				</Button>
			</div>
			{#if quest.objectives}
				<div class="space-y-1">
					{#each quest.objectives as objective, objIndex (objIndex)}
						<div class="flex items-center gap-2">
							<input
								type="checkbox"
								bind:checked={objective.completed}
								class="rounded border-border"
							/>
							<Input bind:value={objective.description} class="h-6 flex-1 text-xs" />
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 text-destructive"
								onclick={() => removeObjective(index, objIndex)}
							>
								<Trash2 class="h-3 w-3" />
							</Button>
						</div>
					{/each}
				</div>
			{/if}
		</div>
	</div>
{/snippet}

{#snippet headerAction()}
	{#if onUpdate}
		{#if isEditing}
			<div class="flex gap-1">
				<Button variant="ghost" size="icon" class="h-6 w-6" onclick={save} title="Save">
					<Save class="h-3.5 w-3.5 text-primary" />
				</Button>
				<Button variant="ghost" size="icon" class="h-6 w-6" onclick={cancel} title="Cancel">
					<X class="h-3.5 w-3.5 text-muted-foreground" />
				</Button>
			</div>
		{:else}
			<Button
				variant="ghost"
				size="icon"
				class="h-6 w-6"
				onclick={startEditing}
				title="Edit Quests"
			>
				<Edit2 class="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />
			</Button>
		{/if}
	{/if}
{/snippet}

<WidgetBase title="Quests" icon={iconSnippet} action={headerAction}>
	<!-- Tabs -->
	<div class="mb-3 flex gap-1 rounded-lg bg-muted p-1">
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'active'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'active')}
		>
			Active ({isEditing ? editActiveQuests.length : activeQuests.length})
		</button>
		<button
			class="flex flex-1 items-center justify-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors {activeTab ===
			'completed'
				? 'bg-primary/20 text-primary'
				: 'text-muted-foreground hover:text-foreground'}"
			onclick={() => (activeTab = 'completed')}
		>
			Completed ({isEditing ? editCompletedQuests.length : completedQuests.length})
		</button>
	</div>

	<!-- Content -->
	<div class="max-h-64 space-y-3 overflow-y-auto">
		{#if isEditing}
			<!-- EDIT MODE -->
			{#if activeTab === 'active'}
				{#each editQuests as quest, i (i)}
					{#if quest.status === 'active'}
						{@render editQuestCard(quest, i)}
					{/if}
				{/each}
			{:else}
				{#each editQuests as quest, i (i)}
					{#if quest.status !== 'active'}
						{@render editQuestCard(quest, i)}
					{/if}
				{/each}
			{/if}
			<Button variant="outline" size="sm" class="h-7 w-full text-xs" onclick={addQuest}>
				<Plus class="mr-1 h-3 w-3" /> Add Quest
			</Button>
		{:else}
			<!-- VIEW MODE -->
			{#if activeTab === 'active'}
				{#if activeQuests.length === 0}
					<p class="py-4 text-center text-sm italic text-muted-foreground">No active quests</p>
				{:else}
					{#each activeQuests as quest (quest.id)}
						{@render questCard(quest)}
					{/each}
				{/if}
			{:else if completedQuests.length === 0}
				<p class="py-4 text-center text-sm italic text-muted-foreground">No completed quests</p>
			{:else}
				{#each completedQuests as quest (quest.id)}
					{@render questCard(quest)}
				{/each}
			{/if}
		{/if}
	</div>
</WidgetBase>
