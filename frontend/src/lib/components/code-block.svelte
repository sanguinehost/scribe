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
	<div
		class="mt-4 w-full rounded-md border border-black/10 bg-black/5 p-2 shadow-sm dark:border-white/10 dark:bg-white/5"
	>
		<code class={cn('whitespace-pre-wrap break-words text-sm', c)} {...rest}>
			{@render children?.()}
		</code>
	</div>
{/if}
