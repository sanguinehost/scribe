<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let { class: className, ...restProps }: { class?: string; [key: string]: unknown } = $props();
</script>

<div class={_cn('-mx-1 my-1 h-px bg-muted', className)} {...restProps}></div>
