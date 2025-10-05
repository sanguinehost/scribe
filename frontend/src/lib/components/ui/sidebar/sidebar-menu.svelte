<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn.js';
	import type { WithElementRef } from 'bits-ui';
	import type { HTMLAttributes } from 'svelte/elements';

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLAttributes<HTMLUListElement>, HTMLUListElement> = $props();
</script>

<ul
	bind:this={ref}
	data-sidebar="menu"
	class={_cn('flex w-full min-w-0 flex-col gap-1', className)}
	{...restProps}
>
	{@render children?.()}
</ul>
