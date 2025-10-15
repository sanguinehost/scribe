<script lang="ts">
	import { Globe } from 'lucide-svelte';
	import Button from '$lib/components/ui/button/button.svelte';

	interface Props {
		onclick?: () => void;
		disabled?: boolean;
	}

	let { onclick, disabled = false }: Props = $props();
</script>

<Button
	variant="outline"
	size="sm"
	class="gap-1.5"
	{onclick}
	{disabled}
	aria-label="Open Web Research Assistant"
>
	<Globe class="h-4 w-4" />
	<span>Research Web</span>
</Button>
