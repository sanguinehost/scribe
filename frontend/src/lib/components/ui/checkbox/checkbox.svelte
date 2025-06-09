<script lang="ts">
	import Check from 'lucide-svelte/icons/check';
	import { cn } from '$lib/utils/shadcn.js';
	import { createEventDispatcher } from 'svelte';

	interface $$Props {
		checked?: boolean;
		disabled?: boolean;
		class?: string;
		id?: string;
	}

	let className: $$Props['class'] = undefined;
	export let checked: $$Props['checked'] = false;
	export let disabled: $$Props['disabled'] = false;
	export let id: $$Props['id'] = undefined;
	export { className as class };

	const dispatch = createEventDispatcher();

	function handleClick() {
		if (!disabled) {
			checked = !checked;
			dispatch('change', checked);
		}
	}
</script>

<button
	type="button"
	role="checkbox"
	aria-checked={checked}
	{disabled}
	{id}
	class={cn(
		'peer box-content h-4 w-4 shrink-0 rounded-sm border border-primary ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
		checked && 'bg-primary text-primary-foreground',
		className
	)}
	onclick={handleClick}
	{...$$restProps}
>
	<div class="flex h-4 w-4 items-center justify-center text-current">
		{#if checked}
			<Check class="h-3.5 w-3.5" />
		{/if}
	</div>
</button>
