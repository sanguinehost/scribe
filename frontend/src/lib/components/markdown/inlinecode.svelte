<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import type { Snippet } from 'svelte';
	import { cn as _cn } from '$lib/utils/shadcn';

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

<code
	class={_cn(
		'bg-muted text-foreground inline break-words rounded px-1.5 py-0.5 font-mono text-sm',
		c
	)}
	{...props}
>
	{#if children}{@render children()}{/if}
</code>

<style>
	code {
		/* Ensure inline code doesn't break line height too much */
		line-height: 1.2;
		/* Slight margin for readability */
		margin: 0 1px;
		/* Better visual separation */
		border: 1px solid hsl(var(--border));
	}

	/* Dark mode adjustments */
	:global(.dark) code {
		background-color: hsl(var(--muted));
		border-color: hsl(var(--border));
	}
</style>
