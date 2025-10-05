<script lang="ts">
	import { Dialog as DialogPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	type $$Props = DialogPrimitive.TitleProps;

	let className: $$Props['class'] = undefined;
	export { className as class };
</script>

<DialogPrimitive.Title
	class={_cn('text-lg font-semibold leading-none tracking-tight', className)}
	{...$$restProps}
>
	<slot />
</DialogPrimitive.Title>
