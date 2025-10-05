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
	}: AlertDialogPrimitive.ActionProps = $props();
</script>

<AlertDialogPrimitive.Action bind:ref class={_cn(buttonVariants(), className)} {...restProps}>
	{@render children?.()}
</AlertDialogPrimitive.Action>
