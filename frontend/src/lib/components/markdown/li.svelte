<script lang="ts">

	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<li {...rest} class={_cn('py-1', rest.class)}>
	{@render children?.()}
</li>
