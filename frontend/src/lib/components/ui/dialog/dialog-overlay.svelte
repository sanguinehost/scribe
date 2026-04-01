<script lang="ts">
	import { Dialog as DialogPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	type $$Props = DialogPrimitive.OverlayProps;

	let className: $$Props['class'] = undefined;
	export { className as class };
</script>

<DialogPrimitive.Overlay
	class={_cn('fixed inset-0 z-50 bg-background/80 backdrop-blur-md transition-all duration-300 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0', className)}
	{...$$restProps}
/>
