<script lang="ts">
	import { Select as SelectPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	type $$Props = SelectPrimitive.GroupHeadingProps;

	let className: $$Props['class'] = undefined;
	export { className as class };
</script>

<SelectPrimitive.GroupHeading
	class={_cn('py-1.5 pl-8 pr-2 text-sm font-semibold', className)}
	{...$$restProps}
>
	<slot />
</SelectPrimitive.GroupHeading>
