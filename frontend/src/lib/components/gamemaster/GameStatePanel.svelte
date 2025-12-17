<script lang="ts">
	import type { GameState } from '$lib/types';
	import { Globe, Layers } from 'lucide-svelte';
	import StatusWidget from './StatusWidget.svelte';
	import CurrencyWidget from './CurrencyWidget.svelte';
	import InventoryWidget from './InventoryWidget.svelte';
	import QuestsWidget from './QuestsWidget.svelte';
	import LocationWidget from './LocationWidget.svelte';
	import NPCsWidget from './NPCsWidget.svelte';

	interface Props {
		gameState: GameState | null;
		isLoading?: boolean;
	}

	let { gameState = null, isLoading = false }: Props = $props();
</script>

<div class="flex h-full flex-col overflow-hidden bg-background text-foreground">
	<!-- Header -->
	<div class="border-b border-border p-4">
		<div class="flex items-center gap-2">
			<div class="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/20">
				<Globe class="h-4 w-4 text-primary" />
			</div>
			<div>
				<h2 class="text-lg font-semibold text-primary">Game Master</h2>
				{#if gameState?.game_time}
					<div class="text-xs text-muted-foreground">
						Day {gameState.game_time.day}, {gameState.game_time.hour}:{String(
							gameState.game_time.minute ?? 0
						).padStart(2, '0')} ({gameState.game_time.period})
					</div>
				{/if}
			</div>
		</div>
	</div>

	{#if isLoading}
		<div class="flex flex-1 items-center justify-center p-8 text-muted-foreground">
			<div
				class="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent"
			></div>
		</div>
	{:else if !gameState}
		<div
			class="flex flex-1 flex-col items-center justify-center p-8 text-center text-muted-foreground"
		>
			<div class="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
				<Layers class="h-8 w-8 text-muted-foreground" />
			</div>
			<p class="text-sm">No game state available</p>
			<p class="mt-1 text-xs text-muted-foreground/70">Enable Game Master Mode to track state</p>
		</div>
	{:else}
		<!-- Scrollable Widget Area -->
		<div class="flex-1 overflow-y-auto p-3">
			<!-- Status / Vitals Widget -->
			<StatusWidget vitals={gameState.vitals} />

			<!-- Currency Widget -->
			<CurrencyWidget currencies={gameState.currencies} />

			<!-- Location Widget -->
			<LocationWidget
				location={gameState.location}
				environment={gameState.environment}
				gameTime={gameState.game_time}
			/>

			<!-- Inventory Widget -->
			<InventoryWidget
				inventory={gameState.inventory}
				inventoryStored={gameState.inventory_stored}
				assets={gameState.assets}
			/>

			<!-- Quests Widget -->
			<QuestsWidget quests={gameState.quests} />

			<!-- NPCs Widget -->
			<NPCsWidget npcs={gameState.npcs} />
		</div>
	{/if}
</div>
