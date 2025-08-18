<script lang="ts">
	import type { StreamingMessage } from '$lib/services/StreamingService.svelte';
	import { Markdown } from '$lib/components/markdown';

	// Props
	let {
		message = $bindable(),
		showTypewriter = false,
		cursorColor = 'orange',
		animationDuration = '2s',
		className = ''
	}: {
		message: StreamingMessage;
		showTypewriter?: boolean;
		cursorColor?: string;
		animationDuration?: string;
		className?: string;
	} = $props();

	// NEW ARCHITECTURE: Use displayedContent for the typewriter effect
	let charCount = $derived(message.displayedContent?.length ?? message.content.length);

	// NEW ARCHITECTURE: Determine if we should show the typewriter effect using isAnimating
	let shouldAnimate = $derived(
		showTypewriter &&
			message.sender === 'assistant' &&
			(message.isAnimating ?? false) && // Use isAnimating for ChatGPT-style animation
			(message.displayedContent?.length ?? message.content.length) > 0
	);

	// Always use markdown rendering for consistency
	let displayContent = $derived(message.displayedContent ?? message.content);

	// Show loading only when we truly have no meaningful content
	let hasTextContent = $derived(displayContent.replace(/\s/g, '').length > 0);
</script>

<div
	class="message-content {className}"
	class:typewriter={shouldAnimate}
	style="--char-count: {charCount}; --cursor-color: {cursorColor}; --animation-duration: {animationDuration}"
>
	<!-- Show loading spinner when no actual text content -->
	{#if !hasTextContent}
		<div class="flex items-center gap-2 py-2 text-muted-foreground">
			<div class="loading-spinner"></div>
			<span class="text-sm">Thinking...</span>
		</div>
	{:else}
		<Markdown md={displayContent} />
	{/if}
</div>

<style>
	.message-content {
		word-wrap: break-word;
		line-height: 1.5;
	}

	/* Fix paragraph spacing in markdown */
	.message-content :global(p) {
		margin-bottom: 1rem;
	}

	.message-content :global(p:last-child) {
		margin-bottom: 0;
	}

	/* Loading spinner */
	.loading-spinner {
		width: 16px;
		height: 16px;
		border: 2px solid transparent;
		border-top: 2px solid currentColor;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		0% {
			transform: rotate(0deg);
		}
		100% {
			transform: rotate(360deg);
		}
	}

	/* Typewriter effect */
	.typewriter {
		position: relative;
	}

	/* Add animated cursor after the content */
	.typewriter::after {
		content: '';
		display: inline-block;
		width: 3px;
		height: 1.2em;
		background-color: var(--cursor-color, orange);
		margin-left: 2px;
		animation: blink 0.75s step-end infinite;
		vertical-align: text-bottom;
	}

	@keyframes blink {
		from,
		to {
			opacity: 1;
		}
		50% {
			opacity: 0;
		}
	}

	/* Remove cursor when not animating */
	.message-content:not(.typewriter)::after {
		display: none;
	}

	/* Responsive adjustments */
	@media (max-width: 768px) {
		.typewriter {
			font-size: 0.95rem;
		}
	}

	/* Dark mode support */
	@media (prefers-color-scheme: dark) {
		.typewriter::after {
			background-color: #fbbf24; /* amber-400 */
		}
	}
</style>
