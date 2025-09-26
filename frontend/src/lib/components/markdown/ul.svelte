<script lang="ts">
	/* eslint-disable svelte/valid-compile */
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest } = $props();
</script>

<ul {...rest} class={_cn('ml-4 list-outside list-decimal', rest.class)}>
	{@render children?.()}
</ul>
