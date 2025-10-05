<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<li {...rest} class={_cn('py-1', rest.class)}>
	{@render children?.()}
</li>
