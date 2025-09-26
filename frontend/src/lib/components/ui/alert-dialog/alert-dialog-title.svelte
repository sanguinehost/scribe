<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { AlertDialog as AlertDialogPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: AlertDialogPrimitive.TitleProps = $props();
</script>

<AlertDialogPrimitive.Title bind:ref class={_cn('text-lg font-semibold', className)} {...restProps}>
	{@render children?.()}
</AlertDialogPrimitive.Title>
