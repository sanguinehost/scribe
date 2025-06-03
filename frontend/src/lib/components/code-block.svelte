<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import type { Snippet } from 'svelte';

	let {
		inline,
		class: c,
		children,
		...rest
	}: {
		inline: boolean;
		class: string;
		children: Snippet;
	} = $props();
</script>

{#if inline}
	<div class="not-prose flex flex-col">
		<pre
			{...rest}
			class={`w-full overflow-x-auto rounded-xl border border-zinc-200 p-4 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-50`}>
          <code class="whitespace-pre-wrap break-words">{@render children?.()}</code>
        </pre>
	</div>
{:else}
	<div class="rounded-md bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 p-2 shadow-sm w-full mt-4">
		<code class={cn('text-sm whitespace-pre-wrap break-words', c)} {...rest}>
			{@render children?.()}
		</code>
	</div>
{/if}
