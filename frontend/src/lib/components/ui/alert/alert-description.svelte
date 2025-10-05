<script lang="ts">
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let className: string | undefined = undefined;
	export { className as class };
</script>

<div class={_cn('text-sm [&_p]:leading-relaxed', className)} {...$$restProps}>
	<slot />
</div>
