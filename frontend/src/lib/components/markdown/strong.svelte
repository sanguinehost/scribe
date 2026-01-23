<script lang="ts">

	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<span {...rest} class={_cn('font-semibold', rest.class)}>
	{@render children?.()}
</span>
