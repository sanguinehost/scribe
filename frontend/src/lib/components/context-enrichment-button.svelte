<script lang="ts">
	import { Button } from './ui/button';
	import Sparkles from './icons/sparkles.svelte';
	import { cn } from '$lib/utils/shadcn';

	type EnrichmentMode = 'disabled' | 'pre_processing' | 'post_processing';

	type Props = {
		value: EnrichmentMode;
		onChange: (mode: EnrichmentMode) => void;
		disabled?: boolean;
	};

	let { value, onChange, disabled = false }: Props = $props();

	// Cycle through modes: disabled → pre_processing → post_processing → disabled
	function cycleMode() {
		if (disabled) return;

		const modes: EnrichmentMode[] = ['disabled', 'pre_processing', 'post_processing'];
		const currentIndex = modes.indexOf(value);
		const nextIndex = (currentIndex + 1) % modes.length;
		onChange(modes[nextIndex]);
	}

	// Get visual properties based on current mode
	const modeConfig = $derived(
		{
			disabled: {
				variant: 'ghost' as const,
				className: 'text-muted-foreground',
				title: 'Context Enrichment: Off - Click to enable pre-processing'
			},
			pre_processing: {
				variant: 'ghost' as const,
				className: 'text-blue-500 hover:text-blue-600',
				title: 'Context Enrichment: Pre-processing - Searching context before response'
			},
			post_processing: {
				variant: 'ghost' as const,
				className: 'text-green-500 hover:text-green-600',
				title: 'Context Enrichment: Post-processing - Enriching context after response'
			}
		}[value]
	);
</script>

<Button
	variant={modeConfig.variant}
	size="sm"
	class={cn('h-7 w-7 p-1.5 transition-colors', modeConfig.className)}
	onclick={cycleMode}
	{disabled}
	title={modeConfig.title}
>
	<Sparkles size={14} />
</Button>
