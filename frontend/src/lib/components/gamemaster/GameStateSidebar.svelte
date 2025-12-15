<script lang="ts">
	import { Button as ButtonComponent } from '../ui/button';
	import { createEventDispatcher } from 'svelte';
	import type { GameState } from '$lib/types';
	import GameStatePanel from './GameStatePanel.svelte';
	import { X } from 'lucide-svelte';

	let {
		isOpen = $bindable(false),
		gameState = null,
		gameTime = null,
		location = null,
		isLoading = false
	}: {
		isOpen?: boolean;
		gameState: GameState | null;
		gameTime?: any;
		location?: any;
		isLoading?: boolean;
	} = $props();

	$inspect(gameState).with((type, value) => {
		console.log(`🔍 GameStateSidebar received ${type}:`, value);
	});

	const dispatch = createEventDispatcher();

	function closeSidebar() {
		isOpen = false;
		dispatch('close');
	}
</script>

<!-- Sidebar Panel -->
{#if isOpen}
	<div
		class="fixed right-0 top-0 z-40 h-full w-96 border-l bg-background shadow-xl transition-transform duration-300 ease-in-out"
		style="transform: translateX(0)"
	>
		<div class="flex h-full flex-col">
			<!-- Header -->
			<div class="flex items-center justify-between border-b p-4">
				<h2 class="text-lg font-semibold">Game Master</h2>
				<ButtonComponent variant="ghost" size="sm" onclick={closeSidebar}>
					<X class="h-4 w-4" />
				</ButtonComponent>
			</div>

			<!-- Game State Panel -->
			<div class="flex-1 overflow-hidden">
				<GameStatePanel {gameState} {isLoading} />
			</div>
		</div>
	</div>
{/if}

<!-- Backdrop -->
{#if isOpen}
	<div
		class="fixed inset-0 z-30 bg-black/20"
		onclick={closeSidebar}
		onkeydown={(e) => e.key === 'Escape' && closeSidebar()}
		role="button"
		tabindex="0"
		aria-label="Close Game Master panel"
	></div>
{/if}
