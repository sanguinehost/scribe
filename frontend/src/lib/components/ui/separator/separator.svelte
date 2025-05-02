<script lang="ts">
	import { cn } from "$lib/utils.js";

	export let orientation: "horizontal" | "vertical" = "horizontal";
</script>

<div
	class={cn(
		"shrink-0 bg-border",
		orientation === "horizontal" ? "h-[1px] w-full" : "h-full w-[1px]",
		$$props.class ?? ""
	)}
	{...$$restProps}
	data-orientation={orientation}
></div> 