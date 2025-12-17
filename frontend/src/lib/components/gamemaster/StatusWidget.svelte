<script lang="ts">
	import type { Vital } from '$lib/types';
	import { Heart } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		vitals?: Record<string, Vital> | null;
	}

	let { vitals = {} }: Props = $props();

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

<WidgetBase title="Status" icon={iconSnippet}>
	<div class="space-y-3">
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
	</div>
</WidgetBase>
