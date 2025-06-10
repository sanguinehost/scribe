<script lang="ts">
	import { Button } from './ui/button';
	import { fly } from 'svelte/transition';
	// import { replaceState } from '$app/navigation'; // No longer needed here
	import type { User } from '$lib/types';

	// Accept sendMessage function and dynamic actions
	let {
		user,
		sendMessage,
		actions
	}: {
		user: User | undefined;
		sendMessage: (content: string) => Promise<void>;
		actions: Array<{ action: string }>; // Expecting array of {action: string}
	} = $props();

	// Removed the static 'suggestedActions' array
</script>

<div class="ml-[40px] grid w-[calc(100%-50px)] gap-2 sm:grid-cols-2">
	{#each actions as suggestedItem, i (suggestedItem.action)}
		<div
			in:fly|global={{ opacity: 0, y: 20, delay: 50 * i, duration: 400 }}
			class={i > 1 ? 'hidden sm:block' : 'block'}
		>
			<!--
				Display logic: Show first two items always.
				Show items 3 and 4 only on 'sm' screens and up.
			-->
			<Button
				variant="ghost"
				onclick={async () => {
					await sendMessage(suggestedItem.action);
				}}
				class="h-auto w-full flex-1 items-start justify-start gap-1 rounded-xl border px-4 py-3.5 text-left text-sm"
				aria-label={`Suggested action: ${suggestedItem.action}`}
			>
				<span class="font-medium">{suggestedItem.action}</span>
				<!-- Removed the second span for 'label' -->
			</Button>
		</div>
	{/each}
</div>
