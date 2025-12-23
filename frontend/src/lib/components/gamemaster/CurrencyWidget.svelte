<script lang="ts">
	import type { GameState } from '$lib/types';
	import { Coins, Edit2, Save, X, Plus, Trash2 } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';

	interface Props {
		currencies?: Record<string, number> | null;
		onUpdate?: (updates: Partial<GameState>) => void;
	}

	let { currencies = {}, onUpdate }: Props = $props();

	let isEditing = $state(false);
	let editCurrencies = $state<Record<string, number>>({});

	function startEditing() {
		editCurrencies = currencies ? { ...currencies } : {};
		isEditing = true;
	}

	function save() {
		if (onUpdate) {
			onUpdate({ currencies: editCurrencies });
		}
		isEditing = false;
	}

	function cancel() {
		isEditing = false;
	}

	function addCurrency() {
		const name = `Currency ${Object.keys(editCurrencies).length + 1}`;
		editCurrencies[name] = 0;
	}

	function removeCurrency(name: string) {
		const newCurrencies = { ...editCurrencies };
		delete newCurrencies[name];
		editCurrencies = newCurrencies;
	}

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
				title="Edit Currencies"
			>
				<Edit2 class="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />
			</Button>
		{/if}
	{/if}
{/snippet}

<WidgetBase title="Currency" icon={iconSnippet} action={headerAction}>
	{#if isEditing}
		<!-- EDIT MODE -->
		<div class="space-y-2">
			{#each Object.entries(editCurrencies) as [name, amount]}
				<div class="flex items-center gap-2 rounded-lg bg-muted/30 p-2">
					<div class="flex-1">
						<Input
							value={name}
							oninput={(e) => {
								const newName = e.currentTarget.value;
								if (newName && newName !== name) {
									const val = editCurrencies[name];
									delete editCurrencies[name];
									editCurrencies[newName] = val;
								}
							}}
							class="h-7 text-xs"
							placeholder="Name"
						/>
					</div>
					<div class="w-24">
						<Input
							type="number"
							bind:value={editCurrencies[name]}
							class="h-7 text-xs"
							placeholder="Amount"
						/>
					</div>
					<Button
						variant="ghost"
						size="icon"
						class="h-7 w-7 text-destructive"
						onclick={() => removeCurrency(name)}
					>
						<Trash2 class="h-3.5 w-3.5" />
					</Button>
				</div>
			{/each}
			<Button variant="outline" size="sm" class="h-7 w-full text-xs" onclick={addCurrency}>
				<Plus class="mr-1 h-3 w-3" /> Add Currency
			</Button>
		</div>
	{:else}
		<!-- VIEW MODE -->
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
	{/if}
</WidgetBase>
