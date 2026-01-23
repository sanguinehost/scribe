<script lang="ts">

	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<h3 {...rest} class={_cn('mb-2 mt-6 text-xl font-semibold', rest.class)}>
	{@render children?.()}
</h3>
