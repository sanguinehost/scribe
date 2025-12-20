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

<div class="bg-background text-foreground flex h-full flex-col overflow-hidden">
	<!-- Header -->
	<div class="border-border border-b p-4">
		<div class="flex items-center gap-2">
			<div class="bg-primary/20 flex h-8 w-8 items-center justify-center rounded-lg">
				<Globe class="text-primary h-4 w-4" />
			</div>
			<div>
				<h2 class="text-primary text-lg font-semibold">Game Master</h2>
				{#if gameState?.game_time}
					<div class="text-muted-foreground text-xs">
						Day {gameState.game_time.day}, {gameState.game_time.hour}:{String(
							gameState.game_time.minute ?? 0
						).padStart(2, '0')} ({gameState.game_time.period})
						{#if gameState.game_time.date}
							<span class="border-border ml-1 border-l pl-1">{gameState.game_time.date}</span>
						{/if}
					</div>
				{/if}
			</div>
		</div>
	</div>

	{#if isLoading}
		<div class="text-muted-foreground flex flex-1 items-center justify-center p-8">
			<div
				class="border-primary h-8 w-8 animate-spin rounded-full border-2 border-t-transparent"
			></div>
		</div>
	{:else if !gameState}
		<div
			class="text-muted-foreground flex flex-1 flex-col items-center justify-center p-8 text-center"
		>
			<div class="bg-muted mb-4 flex h-16 w-16 items-center justify-center rounded-full">
				<Layers class="text-muted-foreground h-8 w-8" />
			</div>
			<p class="text-sm">No game state available</p>
			<p class="text-muted-foreground/70 mt-1 text-xs">Enable Game Master Mode to track state</p>
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
