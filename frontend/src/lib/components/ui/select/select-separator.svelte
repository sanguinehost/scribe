<script lang="ts">
	import { cn } from '$lib/utils/shadcn.js';

	let { class: className, ...restProps }: { class?: string; [key: string]: any } = $props();
</script>

<div class={cn('-mx-1 my-1 h-px bg-muted', className)} {...restProps}></div>
