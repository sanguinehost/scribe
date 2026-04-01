<script lang="ts">
	import type { HTMLAttributes } from 'svelte/elements';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	type $$Props = HTMLAttributes<HTMLDivElement>;

	let className: $$Props['class'] = undefined;
	export { className as class };
</script>

<div
	class={_cn('rounded-xl border border-border/50 bg-card/80 text-card-foreground shadow-lg backdrop-blur-xl ring-1 ring-black/5 dark:ring-white/10 transition-all duration-300', className)}
	{...$$restProps}
>
	<slot />
</div>
