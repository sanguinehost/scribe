<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import type { WithElementRef, WithoutChildren } from 'bits-ui';
	import type { HTMLTextareaAttributes } from 'svelte/elements';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		value = $bindable(),
		class: className,
		...restProps
	}: WithoutChildren<WithElementRef<HTMLTextareaAttributes>> = $props();
</script>

<textarea
	bind:this={ref}
	class={_cn(
		'flex min-h-[80px] w-full rounded-lg border border-border/40 bg-background/50 backdrop-blur-sm shadow-sm transition-all duration-200 px-3 py-2 text-base ring-offset-background placeholder:text-muted-foreground focus-visible:bg-background/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm',
		className
	)}
	bind:value
	{...restProps}
></textarea>
