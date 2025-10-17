<script lang="ts">
	/**
	 * AI Assistant Widget
	 *
	 * Compact button that opens the AI assistant dialog.
	 * Shows readiness state and provides quick access to AI features.
	 */

	import { Button } from '$lib/components/ui/button';
	import { Sparkles } from 'lucide-svelte';

	interface Props {
		/** Optional click handler override */
		onclick?: () => void;
		/** Show as icon-only button (default: true) */
		iconOnly?: boolean;
		/** Size variant */
		size?: 'sm' | 'default' | 'lg';
		/** Variant */
		variant?: 'default' | 'outline' | 'ghost';
		/** Disabled state */
		disabled?: boolean;
	}

	let {
		onclick,
		iconOnly = true,
		size = 'sm',
		variant = 'ghost',
		disabled = false
	}: Props = $props();
</script>

<Button
	{size}
	{variant}
	{disabled}
	class="ai-assistant-widget"
	onclick={() => onclick?.()}
	title="Open AI Assistant"
>
	<Sparkles class="h-4 w-4" />

	{#if !iconOnly}
		<span class="ml-2">AI Assistant</span>
	{/if}
</Button>
