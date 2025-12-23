<script lang="ts">
	import type { Vital, GameState } from '$lib/types';
	import { Heart, Edit2, Save, X, Plus, Trash2 } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';

	interface Props {
		vitals?: Record<string, Vital> | null;
		onUpdate?: (updates: Partial<GameState>) => void;
	}

	let { vitals = {}, onUpdate }: Props = $props();

	let isEditing = $state(false);
	let editVitals = $state<Record<string, Vital>>({});

	function startEditing() {
		// Deep copy vitals
		editVitals = vitals ? JSON.parse(JSON.stringify(vitals)) : {};
		isEditing = true;
	}

	function save() {
		if (onUpdate) {
			onUpdate({ vitals: editVitals });
		}
		isEditing = false;
	}

	function cancel() {
		isEditing = false;
	}

	function addVital() {
		const name = `vital_${Object.keys(editVitals).length + 1}`;
		editVitals[name] = { current: 10, max: 10, modifiers: [], regen_rate: 0 };
	}

	function removeVital(key: string) {
		const newVitals = { ...editVitals };
		delete newVitals[key];
		editVitals = newVitals;
	}

	// Get color gradient based on percentage
	function getVitalColor(current: number, max: number): string {
		const percent = max > 0 ? (current / max) * 100 : 0;
		if (percent > 66) return 'from-emerald-500 to-green-400';
		if (percent > 33) return 'from-yellow-500 to-amber-400';
		return 'from-red-500 to-rose-400';
	}

	// Format vital name for display
	function formatVitalName(key: string): string {
		return key
			.split('_')
			.map((word) => word.charAt(0).toUpperCase() + word.slice(1))
			.join(' ');
	}

	// Get icon for common vital types
	function getVitalIcon(key: string): string {
		const icons: Record<string, string> = {
			health: '❤️',
			hp: '❤️',
			mana: '💠',
			mp: '💠',
			stamina: '⚡',
			energy: '🔋',
			hunger: '🍖',
			thirst: '💧',
			sanity: '🧠',
			stress: '😰'
		};
		return icons[key.toLowerCase()] || '📊';
	}
</script>

{#snippet iconSnippet()}
	<Heart class="h-4 w-4" />
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
				title="Edit Vitals"
			>
				<Edit2 class="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />
			</Button>
		{/if}
	{/if}
{/snippet}

<WidgetBase title="Status" icon={iconSnippet} action={headerAction}>
	<div class="space-y-3">
		{#if isEditing}
			<!-- EDIT MODE -->
			<div class="space-y-3">
				{#each Object.entries(editVitals) as [key, vital]}
					<div class="space-y-2 rounded-lg bg-muted/30 p-2">
						<div class="flex items-center justify-between">
							<div class="flex flex-1 items-center gap-2">
								<span class="text-base">{getVitalIcon(key)}</span>
								<Input
									value={key}
									oninput={(e) => {
										const newKey = e.currentTarget.value;
										if (newKey && newKey !== key) {
											const val = editVitals[key];
											delete editVitals[key];
											editVitals[newKey] = val;
										}
									}}
									class="h-6 w-24 text-xs"
								/>
							</div>
							<Button
								variant="ghost"
								size="icon"
								class="h-6 w-6 text-destructive"
								onclick={() => removeVital(key)}
							>
								<Trash2 class="h-3 w-3" />
							</Button>
						</div>
						<div class="flex items-center gap-2">
							<div class="flex-1">
								<Label class="text-[10px] text-muted-foreground">Current</Label>
								<Input type="number" bind:value={vital.current} class="h-7 text-xs" />
							</div>
							<div class="flex-1">
								<Label class="text-[10px] text-muted-foreground">Max</Label>
								<Input type="number" bind:value={vital.max} class="h-7 text-xs" />
							</div>
						</div>
					</div>
				{/each}
				<Button variant="outline" size="sm" class="h-7 w-full text-xs" onclick={addVital}>
					<Plus class="mr-1 h-3 w-3" /> Add Vital
				</Button>
			</div>
		{:else}
			<!-- VIEW MODE -->
			{#if !vitals || Object.keys(vitals).length === 0}
				<p class="text-center text-sm italic text-muted-foreground">No vitals tracked</p>
			{:else}
				{#each Object.entries(vitals) as [key, vital]}
					{@const percent = vital.max > 0 ? (vital.current / vital.max) * 100 : 0}
					<div class="space-y-1">
						<!-- Label row -->
						<div class="flex items-center justify-between text-xs">
							<span class="flex items-center gap-1.5 font-medium text-foreground">
								<span>{getVitalIcon(key)}</span>
								<span>{formatVitalName(key)}</span>
							</span>
							<span class="font-mono text-muted-foreground">
								{vital.current}/{vital.max}
							</span>
						</div>

						<!-- Progress bar -->
						<div class="h-2.5 overflow-hidden rounded-full bg-muted">
							<div
								class="h-full bg-gradient-to-r transition-all duration-500 ease-out {getVitalColor(
									vital.current,
									vital.max
								)}"
								style="width: {Math.min(100, percent)}%"
							></div>
						</div>

						<!-- Modifiers (if any) -->
						{#if vital.modifiers && vital.modifiers.length > 0}
							<div class="flex flex-wrap gap-1">
								{#each vital.modifiers as modifier}
									<span class="rounded bg-primary/20 px-1.5 py-0.5 text-[10px] text-primary">
										{modifier}
									</span>
								{/each}
							</div>
						{/if}
					</div>
				{/each}
			{/if}
		{/if}
	</div>
</WidgetBase>
