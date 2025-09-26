<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<h4 {...rest} class={_cn('mb-2 mt-6 text-lg font-semibold', rest.class)}>
	{@render children?.()}
</h4>
