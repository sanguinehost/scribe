<script lang="ts">
	import { Button as ButtonComponent } from '../ui/button';
	import { createEventDispatcher } from 'svelte';
	import type { GameState } from '$lib/types';
	import GameStatePanel from './GameStatePanel.svelte';
	import { X, Crown } from 'lucide-svelte';
	import { slideAndFade } from '$lib/utils/transitions';

	let {
		isOpen = $bindable(false),
		gameState = null,
		isLoading = false,
		sessionId = null,
		onStateUpdate
	}: {
		isOpen?: boolean;
		gameState: GameState | null;
		isLoading?: boolean;
		sessionId: string | null;
		onStateUpdate?: (newState: GameState) => void;
	} = $props();



	const dispatch = createEventDispatcher();

	function closeHud() {
		isOpen = false;
		dispatch('close');
	}
</script>

{#if isOpen}
	<div
		in:slideAndFade={{ x: 20, duration: 300 }}
		out:slideAndFade={{ x: 20, duration: 200 }}
		class="z-10 flex h-full w-full flex-col border-l border-border/40 bg-card/60 shadow-lg backdrop-blur-xl transition-all md:w-80 lg:w-96"
	>
		<!-- Header -->
		<div
			class="flex items-center justify-between border-b border-border/40 bg-muted/20 px-4 py-3"
		>
			<div class="flex items-center gap-2">
				<Crown class="h-[18px] w-[18px] text-purple-600 dark:text-purple-400" />
				<h2 class="text-sm font-semibold tracking-tight text-foreground">Game Master HUD</h2>
			</div>
			<ButtonComponent
				variant="ghost"
				size="icon"
				class="h-8 w-8 rounded-full text-muted-foreground transition-colors hover:bg-muted/50 hover:text-foreground"
				onclick={closeHud}
				aria-label="Close GM Panel"
			>
				<X class="h-4 w-4" />
			</ButtonComponent>
		</div>

		<!-- Game State Panel -->
		<div class="flex-1 overflow-y-auto px-4 py-4">
			<GameStatePanel {gameState} {isLoading} {sessionId} {onStateUpdate} />
		</div>
	</div>
{/if}
