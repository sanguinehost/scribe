<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import type { ComponentProps } from 'svelte';
	import { Input } from '$lib/components/ui/input/index.js';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		value = $bindable(''),
		class: className,
		...restProps
	}: ComponentProps<typeof Input> = $props();
</script>

<Input
	bind:ref
	bind:value
	data-sidebar="input"
	class={_cn(
		'h-8 w-full bg-background shadow-none focus-visible:ring-2 focus-visible:ring-sidebar-ring',
		className
	)}
	{...restProps}
/>
