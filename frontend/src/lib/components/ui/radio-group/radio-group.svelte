<script lang="ts">
	// Disable custom elements to avoid props inference issues
	import { RadioGroup as RadioGroupPrimitive } from 'bits-ui';
	import { cn as _cn } from '$lib/utils/shadcn.js';

	let {
		ref = $bindable(null),
		class: className,
		value = $bindable(''),
		...restProps
	}: RadioGroupPrimitive.RootProps = $props();
</script>

<RadioGroupPrimitive.Root bind:ref bind:value class={_cn('grid gap-2', className)} {...restProps} />
