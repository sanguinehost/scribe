<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { Avatar as AvatarPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		src = undefined,
		alt = undefined,
		class: className = undefined,
		...restProps
	}: {
		src?: string | undefined;
		alt?: string | undefined;
		class?: string | undefined;
		[key: string]: unknown;
	} = $props();
</script>

<AvatarPrimitive.Image
	{src}
	{alt}
	class={_cn('aspect-square h-full w-full', className)}
	{...restProps}
/>
