<script lang="ts">
	import type { GameState } from '$lib/types';
	import { Globe, Layers, Edit2, Save, X, AlertTriangle } from 'lucide-svelte';
	import { apiClient } from '$lib/api';
	import { toast } from 'svelte-sonner';
	import StatusWidget from './StatusWidget.svelte';
	import CurrencyWidget from './CurrencyWidget.svelte';
	import InventoryWidget from './InventoryWidget.svelte';
	import QuestsWidget from './QuestsWidget.svelte';
	import LocationWidget from './LocationWidget.svelte';
	import NPCsWidget from './NPCsWidget.svelte';
	import { Button } from '../ui/button';

	interface Props {
		gameState: GameState | null;
		isLoading?: boolean;
		sessionId: string | null;
		onStateUpdate?: (newState: GameState) => void;
	}

	let { gameState = null, isLoading = false, sessionId = null, onStateUpdate }: Props = $props();

	let isEditing = $state(false);
	let editJson = $state('');
	let isSaving = $state(false);

	function startEditing() {
		if (!gameState) return;
		editJson = JSON.stringify(gameState, null, 2);
		isEditing = true;
	}

	function cancelEditing() {
		isEditing = false;
	}

	async function saveChanges() {
		if (!sessionId) return;

		try {
			const parsed = JSON.parse(editJson) as GameState;
			isSaving = true;

			const result = await apiClient.updateGameState(sessionId, parsed);

			if (result.isOk()) {
				toast.success('Game state updated successfully');
				isEditing = false;
				if (onStateUpdate) {
					onStateUpdate(parsed);
				}
			} else {
				toast.error(`Failed to update game state: ${result.error.message}`);
			}
		} catch (e) {
			toast.error(`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`);
		} finally {
			isSaving = false;
		}
	}
	async function handleGranularUpdate(partialState: Partial<GameState>) {
		if (!gameState || !sessionId) return;

		// Create complete new state
		const newState = { ...gameState, ...partialState };

		try {
			const result = await apiClient.updateGameState(sessionId, newState);
			if (result.isOk()) {
				toast.success('Updated');
				if (onStateUpdate) {
					onStateUpdate(newState);
				}
			} else {
				toast.error(`Update failed: ${result.error.message}`);
			}
		} catch (e) {
			toast.error(`Update error: ${e instanceof Error ? e.message : String(e)}`);
		}
	}
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
						{#if gameState.game_time.date}
							<span class="ml-1 border-l border-border pl-1">{gameState.game_time.date}</span>
						{/if}
					</div>
				{/if}
			</div>
		</div>
		<div class="mt-2 flex justify-end gap-2">
			{#if isEditing}
				<Button variant="outline" size="sm" onclick={cancelEditing} disabled={isSaving}>
					<X class="mr-1 h-3 w-3" /> Cancel
				</Button>
				<Button variant="default" size="sm" onclick={saveChanges} disabled={isSaving}>
					<Save class="mr-1 h-3 w-3" />
					{isSaving ? 'Saving...' : 'Save'}
				</Button>
			{:else if gameState}
				<Button
					variant="ghost"
					size="sm"
					onclick={startEditing}
					class="text-xs text-muted-foreground hover:text-primary"
				>
					<Edit2 class="mr-1 h-3 w-3" /> JSON Override
				</Button>
			{/if}
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
	{:else if isEditing}
		<!-- JSON Editor View -->
		<div class="flex flex-1 flex-col overflow-hidden p-4">
			<div
				class="mb-2 flex items-center gap-2 rounded-md bg-amber-500/10 p-2 text-[10px] text-amber-600 dark:text-amber-400"
			>
				<AlertTriangle class="h-3 w-3" />
				<span>Warning: Manual overrides bypass AI reconciliation. Use valid JSON.</span>
			</div>
			<textarea
				bind:value={editJson}
				class="flex-1 rounded-md border border-border bg-muted p-3 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-primary"
				spellcheck="false"
			></textarea>
		</div>
	{:else}
		<!-- Scrollable Widget Area -->
		<div class="flex-1 overflow-y-auto p-3">
			<!-- Status / Vitals Widget -->
			<StatusWidget
				vitals={gameState.vitals}
				onUpdate={(updates) => handleGranularUpdate(updates)}
			/>

			<!-- Currency Widget -->
			<CurrencyWidget
				currencies={gameState.currencies}
				onUpdate={(updates) => handleGranularUpdate(updates)}
			/>

			<!-- Location Widget -->
			<LocationWidget
				location={gameState.location}
				environment={gameState.environment}
				gameTime={gameState.game_time}
				onUpdate={(updates) => handleGranularUpdate(updates)}
			/>

			<!-- Inventory Widget -->
			<InventoryWidget
				inventory={gameState.inventory}
				inventoryStored={gameState.inventory_stored}
				assets={gameState.assets}
				onUpdate={(updates) => handleGranularUpdate(updates)}
			/>

			<!-- Quests Widget -->
			<QuestsWidget
				quests={gameState.quests}
				onUpdate={(updates) => handleGranularUpdate(updates)}
			/>

			<!-- NPCs Widget -->
			<NPCsWidget
				npcs={Object.values(gameState.npcs || {})}
				currentLocationName={gameState.location?.name}
				onUpdate={(updates) => handleGranularUpdate(updates)}
			/>
		</div>
	{/if}
</div>
