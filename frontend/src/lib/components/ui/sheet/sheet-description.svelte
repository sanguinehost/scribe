<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { Dialog as SheetPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: SheetPrimitive.DescriptionProps = $props();
</script>

<SheetPrimitive.Description
	bind:ref
	class={_cn('text-sm text-muted-foreground', className)}
	{...restProps}
/>
