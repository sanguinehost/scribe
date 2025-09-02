<script lang="ts">
	import { Avatar as AvatarPrimitive } from 'bits-ui';
	import { cn } from '$lib/utils/shadcn.js';

	let {
		src = undefined,
		alt = undefined,
		class: className = undefined,
		...restProps
	}: {
		src?: string | undefined;
		alt?: string | undefined;
		class?: string | undefined;
		[key: string]: any;
	} = $props();
</script>

<AvatarPrimitive.Image
	{src}
	{alt}
	class={cn('aspect-square h-full w-full', className)}
	{...restProps}
/>
