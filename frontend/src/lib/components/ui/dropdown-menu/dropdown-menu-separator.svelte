<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: DropdownMenuPrimitive.SeparatorProps = $props();
</script>

<DropdownMenuPrimitive.Separator
	bind:ref
	class={_cn('-mx-1 my-1 h-px bg-muted', className)}
	{...restProps}
/>
