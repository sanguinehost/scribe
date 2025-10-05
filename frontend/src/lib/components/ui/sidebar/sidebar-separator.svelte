<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { Separator } from '$lib/components/ui/separator/index.js';
	import { cn as _cn } from '$lib/utils/shadcn.js';
	import type { ComponentProps } from 'svelte';

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: ComponentProps<typeof Separator> = $props();
</script>

<Separator
	bind:ref
	data-sidebar="separator"
	class={_cn('mx-2 w-auto bg-sidebar-border', className)}
	{...restProps}
/>
