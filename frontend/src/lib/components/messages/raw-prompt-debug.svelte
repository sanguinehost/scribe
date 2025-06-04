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
		class="ring-offset-background focus-visible:ring-ring inline-flex items-center gap-2 whitespace-nowrap font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 hover:bg-accent rounded-md px-3 h-8 w-full justify-between text-xs text-muted-foreground hover:text-foreground"
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
				<div class="text-xs font-medium text-muted-foreground mb-2">Raw Prompt Sent to AI:</div>
				<pre class="text-xs whitespace-pre-wrap break-words font-mono leading-relaxed text-muted-foreground overflow-x-auto max-h-96 overflow-y-auto">{rawPrompt}</pre>
			</div>
		</div>
	{/if}
</div>