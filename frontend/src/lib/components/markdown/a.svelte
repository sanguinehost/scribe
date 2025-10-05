<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<a
	{...rest}
	class={_cn('text-blue-500 hover:underline', rest.class)}
	target="_blank"
	rel="noopener noreferrer"
>
	{@render children?.()}
</a>
