<script lang="ts">
	let {
		children,
		class: c,
		...props
	}: {
		children: any;
		class?: string;
		[key: string]: any;
	} = $props();
</script>

<div class="not-prose mt-4 flex flex-col">
	<pre
		class="w-full overflow-x-auto rounded-xl border border-zinc-200 p-4 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-50"
		{...props}>
		{@render children?.()}
	</pre>
</div>
