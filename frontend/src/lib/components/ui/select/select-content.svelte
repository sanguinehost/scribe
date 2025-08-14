<script lang="ts">
	import { Select as SelectPrimitive } from 'bits-ui';
	import { cn } from '$lib/utils/shadcn.js';

	type $$Props = SelectPrimitive.ContentProps;

	export let sideOffset: $$Props['sideOffset'] = 4;
	let className: $$Props['class'] = undefined;
	export { className as class };
</script>

<SelectPrimitive.Content
	{sideOffset}
	class={cn(
		'relative z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md outline-none',
		className
	)}
	{...$$restProps}
>
	<div class="w-full p-1">
		<slot />
	</div>
</SelectPrimitive.Content>
