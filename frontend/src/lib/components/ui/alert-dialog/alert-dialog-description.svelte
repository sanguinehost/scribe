<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { AlertDialog as AlertDialogPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: AlertDialogPrimitive.DescriptionProps = $props();
</script>

<AlertDialogPrimitive.Description
	bind:ref
	class={_cn('text-sm text-muted-foreground', className)}
	{...restProps}
>
	{@render children?.()}
</AlertDialogPrimitive.Description>
