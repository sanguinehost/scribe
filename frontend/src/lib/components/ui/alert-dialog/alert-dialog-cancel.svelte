<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { AlertDialog as AlertDialogPrimitive } from 'bits-ui';
	import { buttonVariants } from '$lib/components/ui/button/index.js';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: AlertDialogPrimitive.CancelProps = $props();
</script>

<AlertDialogPrimitive.Cancel
	bind:ref
	class={_cn(buttonVariants({ variant: 'outline' }), 'mt-2 sm:mt-0', className)}
	{...restProps}
>
	{@render children?.()}
</AlertDialogPrimitive.Cancel>
