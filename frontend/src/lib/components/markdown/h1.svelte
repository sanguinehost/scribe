<script lang="ts">

	// Disable custom elements to avoid props inference issues
	import type { Snippet } from 'svelte';
	import { cn as _cn } from '$lib/utils/shadcn';

	let { children, ...rest }: { children?: Snippet; [key: string]: unknown } = $props();
</script>

<h1
	{...rest}
	class={_cn(
		'mb-2 mt-6 text-3xl font-semibold',
		typeof rest.class === 'string' ? rest.class : undefined
	)}
>
	{@render children?.()}
</h1>
