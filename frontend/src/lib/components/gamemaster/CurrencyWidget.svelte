<script lang="ts">
	import { Coins } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		currencies?: Record<string, number> | null;
	}

	let { currencies = {} }: Props = $props();

	// Format large numbers with commas
	function formatAmount(amount: number): string {
		return amount.toLocaleString();
	}

	// Get appropriate emoji for common currency types
	function getCurrencyEmoji(name: string): string {
		const lower = name.toLowerCase();
		if (lower.includes('gold') || lower.includes('coin')) return '🪙';
		if (lower.includes('silver')) return '🥈';
		if (lower.includes('copper') || lower.includes('bronze')) return '🥉';
		if (lower.includes('platinum') || lower.includes('plat')) return '💎';
		if (lower.includes('credit')) return '💳';
		if (lower.includes('gem') || lower.includes('jewel')) return '💎';
		if (lower.includes('soul')) return '👻';
		if (lower.includes('energy') || lower.includes('mana')) return '⚡';
		return '💰';
	}

	const currencyEntries = $derived(Object.entries(currencies || {}));
</script>

{#snippet iconSnippet()}
	<Coins class="h-4 w-4" />
{/snippet}

<WidgetBase title="Currency" icon={iconSnippet}>
	{#if currencyEntries.length === 0}
		<p class="py-2 text-center text-sm italic text-muted-foreground">No currencies tracked</p>
	{:else}
		<div class="flex flex-wrap gap-2">
			{#each currencyEntries as [name, amount]}
				<div
					class="flex items-center gap-1.5 rounded-md bg-muted/50 px-2.5 py-1.5 text-sm"
					title={name}
				>
					<span class="text-base">{getCurrencyEmoji(name)}</span>
					<span class="font-semibold text-foreground">{formatAmount(amount)}</span>
					<span class="text-xs text-muted-foreground">{name}</span>
				</div>
			{/each}
		</div>
	{/if}
</WidgetBase>
