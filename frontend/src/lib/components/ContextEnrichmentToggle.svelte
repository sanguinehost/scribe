<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button } from './ui/button';
	import { cn } from '$lib/utils/shadcn';

	type EnrichmentMode = 'disabled' | 'pre_processing' | 'post_processing';

	let {
		value = $bindable('disabled' as EnrichmentMode),
		disabled = false,
		compact = false,
		class: className = ''
	}: {
		value?: EnrichmentMode;
		disabled?: boolean;
		compact?: boolean;
		class?: string;
	} = $props();

	const dispatch = createEventDispatcher<{
		change: { mode: EnrichmentMode };
	}>();

	function handleModeChange(mode: EnrichmentMode) {
		if (disabled) return;
		value = mode;
		dispatch('change', { mode });
	}

	// Labels for different display modes
	const labels = {
		full: {
			disabled: 'Off',
			pre_processing: 'Pre-process',
			post_processing: 'Post-process'
		},
		compact: {
			disabled: 'Off',
			pre_processing: 'Pre',
			post_processing: 'Post'
		}
	};

	const descriptions = {
		disabled: 'No automatic context enrichment',
		pre_processing: 'Search context before response',
		post_processing: 'Enrich context after response'
	};

	const currentLabels = $derived(compact ? labels.compact : labels.full);
</script>

<div class={cn('flex items-center gap-1', className)}>
	{#if !compact}
		<span class="mr-2 text-sm text-muted-foreground">Context:</span>
	{/if}

	<div class="inline-flex rounded-md shadow-sm" role="group">
		<Button
			variant={value === 'disabled' ? 'default' : 'outline'}
			size="sm"
			onclick={() => handleModeChange('disabled')}
			{disabled}
			title={descriptions.disabled}
			class={cn('rounded-r-none border-r-0', value === 'disabled' && 'font-semibold')}
		>
			{currentLabels.disabled}
		</Button>

		<Button
			variant={value === 'pre_processing' ? 'default' : 'outline'}
			size="sm"
			onclick={() => handleModeChange('pre_processing')}
			{disabled}
			title={descriptions.pre_processing}
			class={cn('rounded-none border-r-0', value === 'pre_processing' && 'font-semibold')}
		>
			{currentLabels.pre_processing}
		</Button>

		<Button
			variant={value === 'post_processing' ? 'default' : 'outline'}
			size="sm"
			onclick={() => handleModeChange('post_processing')}
			{disabled}
			title={descriptions.post_processing}
			class={cn('rounded-l-none', value === 'post_processing' && 'font-semibold')}
		>
			{currentLabels.post_processing}
		</Button>
	</div>
</div>
