<script lang="ts">
	import type { NpcState, GameState } from '$lib/types';
	import { Users, User, Edit2, Save, X, Plus, Trash2, MapPin } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';
	import { Textarea } from '../ui/textarea';
	import { Label } from '../ui/label';

	interface Props {
		npcs?: NpcState[] | null;
		currentLocationName?: string | null;
		onUpdate?: (updates: Partial<GameState>) => void;
	}

	let { npcs = [], currentLocationName = null, onUpdate }: Props = $props();

	// Filter NPCs by location in view mode
	const npcList = $derived(
		(npcs ?? []).filter((npc) => {
			if (!currentLocationName || !npc.location) return true;
			return (
				npc.location.toLowerCase().includes(currentLocationName.toLowerCase()) ||
				currentLocationName.toLowerCase().includes(npc.location.toLowerCase())
			);
		})
	);

	let isEditing = $state(false);
	let editNpcs = $state<NpcState[]>([]);

	function startEditing() {
		editNpcs = npcs ? JSON.parse(JSON.stringify(npcs)) : [];
		isEditing = true;
	}

	function save() {
		if (onUpdate) {
			const npcsRecord: Record<string, NpcState> = {};
			editNpcs.forEach((npc) => {
				npcsRecord[npc.id] = npc;
			});
			onUpdate({ npcs: npcsRecord });
		}
		isEditing = false;
	}

	function cancel() {
		isEditing = false;
	}

	function addNpc() {
		const newNpc: NpcState = {
			id: crypto.randomUUID(),
			name: 'New NPC',
			role: 'Villager',
			location: currentLocationName || 'Unknown',
			status: 'neutral',
			disposition: 'neutral',
			description: '',
			personality: '',
			is_important: false,
			objectives: [],
			data: {}
		};
		editNpcs.push(newNpc);
	}

	function removeNpc(index: number) {
		editNpcs = editNpcs.filter((_, i) => i !== index);
	}

	// Get status color
	function getStatusColor(status: string): string {
		const s = status.toLowerCase();
		if (s === 'hostile' || s === 'enemy') return 'text-destructive';
		if (s === 'friendly' || s === 'ally') return 'text-green-500';
		if (s === 'neutral') return 'text-muted-foreground';
		return 'text-foreground';
	}
</script>

{#snippet iconSnippet()}
	<Users class="h-4 w-4" />
{/snippet}

{#snippet npcCard(npc: NpcState)}
	<div class="rounded-lg border border-border bg-muted/50 p-2">
		<div class="flex items-start gap-2">
			<div class="flex h-8 w-8 items-center justify-center rounded bg-muted">
				<User class="h-4 w-4 text-muted-foreground" />
			</div>
			<div class="min-w-0 flex-1">
				<div class="flex items-center justify-between gap-2">
					<h4 class="truncate text-sm font-medium text-foreground">{npc.name}</h4>
					<span class="text-[10px] uppercase tracking-wider {getStatusColor(npc.status)}">
						{npc.status}
					</span>
				</div>
				<p class="truncate text-xs text-muted-foreground">{npc.role} • {npc.location}</p>
				{#if npc.description}
					<p class="mt-1 line-clamp-2 text-[10px] text-muted-foreground/80">{npc.description}</p>
				{/if}
			</div>
		</div>
	</div>
{/snippet}

{#snippet editNpcCard(npc: NpcState, index: number)}
	<div class="space-y-3 rounded-lg border border-border bg-muted/30 p-3">
		<div class="flex items-center gap-2">
			<Input bind:value={npc.name} class="h-7 flex-1 text-xs font-medium" placeholder="Name" />
			<Input bind:value={npc.status} class="h-7 w-20 text-xs" placeholder="Status" />
			<Button
				variant="ghost"
				size="icon"
				class="h-7 w-7 text-destructive"
				onclick={() => removeNpc(index)}
			>
				<Trash2 class="h-3.5 w-3.5" />
			</Button>
		</div>

		<div class="flex items-center gap-2">
			<Input bind:value={npc.role} class="h-7 flex-1 text-xs" placeholder="Role" />
			<div class="flex flex-1 gap-1">
				<Input bind:value={npc.location} class="h-7 flex-1 text-xs" placeholder="Location" />
				{#if currentLocationName && npc.location !== currentLocationName}
					<Button
						variant="outline"
						size="icon"
						class="h-7 w-7"
						title="Move to current location"
						onclick={() => (npc.location = currentLocationName)}
					>
						<MapPin class="h-3.5 w-3.5" />
					</Button>
				{/if}
			</div>
		</div>

		<div class="flex items-center gap-2">
			<label class="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
				<input type="checkbox" bind:checked={npc.is_important} class="rounded border-border" />
				Important (Persists when absent)
			</label>
		</div>

		<div class="space-y-2">
			<div>
				<Label class="text-[10px] text-muted-foreground">Description</Label>
				<Textarea
					bind:value={npc.description}
					class="min-h-[40px] text-xs"
					placeholder="Description"
				/>
			</div>
			<div>
				<Label class="text-[10px] text-muted-foreground">Personality</Label>
				<Textarea
					bind:value={npc.personality}
					class="min-h-[40px] text-xs"
					placeholder="Personality"
				/>
			</div>
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
			<Button variant="ghost" size="icon" class="h-6 w-6" onclick={startEditing} title="Edit NPCs">
				<Edit2 class="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />
			</Button>
		{/if}
	{/if}
{/snippet}

<WidgetBase title="NPCs" icon={iconSnippet} action={headerAction}>
	<div class="max-h-64 space-y-2 overflow-y-auto">
		{#if isEditing}
			<!-- EDIT MODE -->
			<div class="space-y-4">
				<!-- Current Location NPCs -->
				<div>
					<h4 class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
						Here
					</h4>
					<div class="space-y-3">
						{#each editNpcs.filter((n) => !currentLocationName || (n.location && n.location.includes(currentLocationName))) as npc, i (i)}
							{@render editNpcCard(npc, editNpcs.indexOf(npc))}
						{/each}
						<Button variant="outline" size="sm" class="h-7 w-full text-xs" onclick={addNpc}>
							<Plus class="mr-1 h-3 w-3" /> Add NPC Here
						</Button>
					</div>
				</div>

				<!-- Other NPCs -->
				{#if editNpcs.some((n) => currentLocationName && (!n.location || !n.location.includes(currentLocationName)))}
					<div class="border-t border-border pt-2">
						<h4 class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
							Elsewhere
						</h4>
						<div class="space-y-3">
							{#each editNpcs.filter((n) => currentLocationName && (!n.location || !n.location.includes(currentLocationName))) as npc, i (i)}
								{@render editNpcCard(npc, editNpcs.indexOf(npc))}
							{/each}
						</div>
					</div>
				{/if}
			</div>
		{:else}
			<!-- VIEW MODE -->
			{#if npcList.length === 0}
				<p class="py-4 text-center text-sm italic text-muted-foreground">No NPCs nearby</p>
			{:else}
				{#each npcList as npc (npc.id)}
					{@render npcCard(npc)}
				{/each}
			{/if}
		{/if}
	</div>
</WidgetBase>
