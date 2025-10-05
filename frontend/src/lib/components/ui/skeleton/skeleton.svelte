<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import type { WithElementRef, WithoutChildren } from 'bits-ui';
	import type { HTMLAttributes } from 'svelte/elements';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: WithoutChildren<WithElementRef<HTMLAttributes<HTMLDivElement>>> = $props();
</script>

<div
	bind:this={ref}
	class={_cn('animate-pulse rounded-md bg-muted', className)}
	{...restProps}
></div>
