<script lang="ts">
	import ChevronDownIcon from '../icons/chevron-down.svelte';
	import ChevronUpIcon from '../icons/chevron-up.svelte';
	import { slide } from 'svelte/transition';

	let { rawPrompt }: { rawPrompt: string } = $props();

	let isOpen = $state(false);

	function toggleOpen() {
		isOpen = !isOpen;
	}
</script>

<div class="w-full">
	<button
		onclick={toggleOpen}
		type="button"
		class="inline-flex h-8 w-full items-center justify-between gap-2 whitespace-nowrap rounded-md px-3 text-xs font-medium text-muted-foreground ring-offset-background transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
	>
		<span>Show raw prompt debug info</span>
		{#if isOpen}
			<ChevronUpIcon size={12} />
		{:else}
			<ChevronDownIcon size={12} />
		{/if}
	</button>

	{#if isOpen}
		<div class="mt-2" transition:slide={{ duration: 200 }}>
			<div class="rounded-md border bg-muted/30 p-3">
				<div class="mb-2 text-xs font-medium text-muted-foreground">Raw Prompt Sent to AI:</div>
				<pre
					class="max-h-96 overflow-x-auto overflow-y-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-muted-foreground">{rawPrompt}</pre>
			</div>
		</div>
	{/if}
</div>
