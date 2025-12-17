<script lang="ts">
	import type { NpcState } from '$lib/types';
	import { Users } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		npcs?: Record<string, NpcState> | null;
	}

	let { npcs = {} }: Props = $props();

	const npcList = $derived(Object.entries(npcs || {}));

	// Get disposition emoji and color (inspired by rpg-companion relationship emojis)
	function getDispositionStyle(disposition: string): {
		emoji: string;
		color: string;
		border: string;
	} {
		const lower = disposition?.toLowerCase() || 'neutral';
		if (lower.includes('friend') || lower.includes('ally') || lower.includes('loyal')) {
			return { emoji: '💚', color: 'text-green-500', border: 'border-green-500/30' };
		}
		if (lower.includes('love') || lower.includes('romantic') || lower.includes('intimate')) {
			return { emoji: '❤️', color: 'text-pink-500', border: 'border-pink-500/30' };
		}
		if (lower.includes('hostile') || lower.includes('enemy') || lower.includes('aggressive')) {
			return { emoji: '⚔️', color: 'text-red-500', border: 'border-red-500/30' };
		}
		if (lower.includes('wary') || lower.includes('suspicious') || lower.includes('cautious')) {
			return { emoji: '👁️', color: 'text-yellow-500', border: 'border-yellow-500/30' };
		}
		// Neutral / Unknown
		return { emoji: '⚖️', color: 'text-muted-foreground', border: 'border-border' };
	}

	// Get status icon
	function getStatusIcon(status: string): string {
		const lower = status?.toLowerCase() || 'alive';
		if (lower.includes('dead') || lower.includes('deceased')) return '💀';
		if (lower.includes('unconscious') || lower.includes('sleeping')) return '😴';
		if (lower.includes('injured') || lower.includes('wounded')) return '🩹';
		if (lower.includes('missing') || lower.includes('gone')) return '❓';
		return ''; // Alive - no special icon
	}
</script>

{#snippet iconSnippet()}
	<Users class="h-4 w-4" />
{/snippet}

<WidgetBase title="NPCs" icon={iconSnippet}>
	{#if npcList.length === 0}
		<p class="py-4 text-center text-sm italic text-muted-foreground">No NPCs nearby</p>
	{:else}
		<div class="max-h-48 space-y-2 overflow-y-auto">
			{#each npcList as [id, npc]}
				{@const style = getDispositionStyle(npc.disposition)}
				{@const statusIcon = getStatusIcon(npc.status)}
				<div
					class="rounded-lg border bg-muted/50 p-2.5 transition-colors hover:bg-muted {style.border}"
				>
					<!-- Name and Disposition -->
					<div class="flex items-center gap-2">
						<span class="text-base">{style.emoji}</span>
						<div class="min-w-0 flex-1">
							<div class="flex items-center gap-2">
								<span class="truncate text-sm font-medium text-foreground">
									{npc.name || id}
								</span>
								{#if statusIcon}
									<span class="text-sm" title={npc.status}>{statusIcon}</span>
								{/if}
							</div>
							<div class="text-xs capitalize text-muted-foreground">
								{npc.disposition || 'Unknown'}
							</div>
						</div>
					</div>

					<!-- Location & Status -->
					{#if npc.location || npc.status}
						<div class="mt-1.5 flex flex-wrap gap-2 text-xs">
							{#if npc.location}
								<span class="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
									📍 {npc.location}
								</span>
							{/if}
							{#if npc.status && !statusIcon}
								<span class="rounded bg-muted px-1.5 py-0.5 capitalize text-muted-foreground">
									{npc.status}
								</span>
							{/if}
						</div>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</WidgetBase>
