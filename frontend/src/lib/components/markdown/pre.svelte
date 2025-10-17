<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import type { Snippet } from 'svelte';

	let {
		children,
		class: c,
		...props
	}: {
		children?: Snippet;
		class?: string;
		[key: string]: unknown;
	} = $props();
</script>

<div class="not-prose mt-4 flex flex-col">
	<pre
		class="w-full overflow-x-auto rounded-xl border border-zinc-200 p-4 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-50"
		{...props}>{@render children?.()}</pre>
</div>
