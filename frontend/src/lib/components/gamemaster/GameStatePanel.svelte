<script lang="ts">
	import type { GameState } from '$lib/types';
	import StatusWidget from './StatusWidget.svelte';
	import InventoryWidget from './InventoryWidget.svelte';
	import QuestsWidget from './QuestsWidget.svelte';
	import LocationWidget from './LocationWidget.svelte';

	interface Props {
		gameState: GameState | null;
		isLoading?: boolean;
	}

	let { gameState = null, isLoading = false }: Props = $props();
</script>

<div class="flex h-full flex-col overflow-hidden bg-gray-900 text-gray-100">
	<!-- Header -->
	<div class="border-b border-gray-800 p-4">
		<div class="flex items-center gap-2">
			<div class="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-500/20">
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-4 w-4 text-purple-400"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
				>
					<path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"></path>
					<path d="M2 12h20"></path>
					<path
						d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"
					></path>
				</svg>
			</div>
			<div>
				<h2 class="text-lg font-semibold text-purple-400">Game Master</h2>
				{#if gameState?.game_time}
					<div class="text-xs text-gray-400">
						Day {gameState.game_time.day}, {gameState.game_time.hour}:00 ({gameState.game_time
							.period})
					</div>
				{/if}
			</div>
		</div>
	</div>

	{#if isLoading}
		<div class="flex flex-1 items-center justify-center p-8 text-gray-500">
			<div
				class="h-8 w-8 animate-spin rounded-full border-2 border-purple-500 border-t-transparent"
			></div>
		</div>
	{:else if !gameState}
		<div class="flex flex-1 flex-col items-center justify-center p-8 text-center text-gray-500">
			<div class="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-gray-800">
				<svg
					xmlns="http://www.w3.org/2000/svg"
					class="h-8 w-8 text-gray-600"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="1.5"
				>
					<path d="M12 2L2 7l10 5 10-5-10-5z"></path>
					<path d="M2 17l10 5 10-5"></path>
					<path d="M2 12l10 5 10-5"></path>
				</svg>
			</div>
			<p class="text-sm">No game state available</p>
			<p class="mt-1 text-xs text-gray-600">Enable Game Master Mode to track state</p>
		</div>
	{:else}
		<!-- Scrollable Widget Area -->
		<div class="flex-1 overflow-y-auto p-3">
			<!-- Status / Vitals Widget -->
			<StatusWidget vitals={gameState.vitals} />

			<!-- Location Widget -->
			<LocationWidget
				location={gameState.location}
				environment={gameState.environment}
				gameTime={gameState.game_time}
			/>

			<!-- Inventory Widget -->
			<InventoryWidget inventory={gameState.inventory} />

			<!-- Quests Widget -->
			<QuestsWidget quests={gameState.quests} />
		</div>
	{/if}
</div>
