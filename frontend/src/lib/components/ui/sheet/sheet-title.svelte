<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { Dialog as SheetPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		...restProps
	}: SheetPrimitive.TitleProps = $props();
</script>

<SheetPrimitive.Title
	bind:ref
	class={_cn('text-lg font-semibold text-foreground', className)}
	{...restProps}
/>
