<script lang="ts">
	import { cn } from '$lib/utils/shadcn';

	let {
		children,
		class: c,
		...props
	}: {
		children: any;
		class?: string;
		[key: string]: any;
	} = $props();
</script>

<code
	class={cn(
		'inline-block rounded bg-muted px-1.5 py-0.5 text-sm font-mono text-foreground break-words',
		c
	)}
	{...props}
>
	{@render children?.()}
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