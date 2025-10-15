<script lang="ts">
	/**
	 * AI Assistant Widget
	 *
	 * Compact button that opens the AI assistant dialog.
	 * Shows readiness state and provides quick access to AI features.
	 */

	import { Button } from '$lib/components/ui/button';
	import { Sparkles, AlertCircle } from 'lucide-svelte';
	import { isGenerationReady } from '$lib/utils/ai/generation-engine';

	interface Props {
		/** Optional click handler override */
		onclick?: () => void;
		/** Show as icon-only button (default: true) */
		iconOnly?: boolean;
		/** Size variant */
		size?: 'sm' | 'default' | 'lg';
		/** Variant */
		variant?: 'default' | 'outline' | 'ghost';
	}

	let { onclick, iconOnly = true, size = 'sm', variant = 'ghost' }: Props = $props();

	// Check if AI is ready
	const readiness = $derived(isGenerationReady());
	const isReady = $derived(readiness.ready);
	const notReadyReason = $derived(readiness.reason);
</script>

<Button
	{size}
	{variant}
	class="ai-assistant-widget"
	onclick={() => onclick?.()}
	disabled={!isReady}
	title={isReady ? 'Open AI Assistant' : notReadyReason}
>
	{#if isReady}
		<Sparkles class="h-4 w-4" />
	{:else}
		<AlertCircle class="h-4 w-4 text-muted-foreground" />
	{/if}

	{#if !iconOnly}
		<span class="ml-2">AI Assistant</span>
	{/if}
</Button>
