<script lang="ts">
	import type { HTMLAttributes } from 'svelte/elements';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	type $$Props = HTMLAttributes<HTMLDivElement>;

	let className: $$Props['class'] = undefined;
	export { className as class };
</script>

<div
	class={_cn('flex flex-col-reverse sm:flex-row sm:justify-end sm:space-x-2', className)}
	{...$$restProps}
>
	<slot />
</div>
