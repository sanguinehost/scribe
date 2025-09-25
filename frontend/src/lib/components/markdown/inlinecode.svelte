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
		'inline-block break-words rounded bg-muted px-1.5 py-0.5 font-mono text-sm text-foreground',
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
