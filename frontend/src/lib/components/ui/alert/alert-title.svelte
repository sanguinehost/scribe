<script lang="ts">
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let className: string | undefined = undefined;
	export { className as class };
</script>

<h5 class={_cn('mb-1 font-medium leading-none tracking-tight', className)} {...$$restProps}>
	<slot />
</h5>
