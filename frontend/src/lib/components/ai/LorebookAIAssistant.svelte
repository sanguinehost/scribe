<script lang="ts">
	import { Sparkles } from '@lucide/svelte';
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
	aria-label="Open AI Lorebook Assistant"
>
	<Sparkles class="h-4 w-4" />
	<span>AI Assistant</span>
</Button>
