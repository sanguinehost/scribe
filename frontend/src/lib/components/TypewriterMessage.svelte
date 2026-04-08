<script lang="ts">
	import { activeStreamingService as streamingService, type StreamingMessage } from '$lib/services/StreamingService.svelte';
	import { Markdown } from '$lib/components/markdown';
	import StatsWidget from '$lib/components/widgets/StatsWidget.svelte';
	import { segmentMessageContent, type ContentSegment } from '$lib/utils/parsers/widget-parser';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { untrack } from 'svelte';
	import { fade } from 'svelte/transition';

	// Props
	let {
		message = $bindable(),
		cursorColor = 'orange',
		className = '',
		onRepairFormat
	}: {
		message: StreamingMessage;
		cursorColor?: string;
		className?: string;
		onRepairFormat?: (messageId: string) => void;
	} = $props();

	// Get settings store for typing speed
	let settingsStore: SettingsStore | null = null;
	try {
		settingsStore = SettingsStore.fromContext();
	} catch {
		// Settings store not available in this context
		console.warn('SettingsStore not available in TypewriterMessage context');
	}

	// Animation state
	let displayedContent = $state('');
	let isAnimating = $state(false);
	let animationFrameId = $state<number | null>(null);
	let startTime = $state<number | null>(null);
	let startCharIndex = $state(0); // Track where animation started from
	let animationInitialized = $state(false); // Gate to prevent flicker before first frame

	// Track the last content we've processed
	let lastProcessedContent = $state('');

	// Reactive typing speed from settings store
	let typingSpeed = $derived(settingsStore?.typingSpeed ?? 30);

	// Parse segments dynamically
	const textSegments = $derived(segmentMessageContent(displayedContent));

	// Derived state
	let charCount = $derived(displayedContent.length);
	let shouldShowTypewriter = $derived(
		message?.sender === 'assistant' && isAnimating && displayedContent.length > 0
	);

	// Show loading when no content or regenerating
	// CRITICAL: Add null guards to prevent TypeError when message is undefined during reactive updates
	// ALSO: Don't show loading spinner if reasoning content is active (the reasoning block handles its own indicator)
	let hasTextContent = $derived((message?.content || '').replace(/\s/g, '').length > 0);
	let hasReasoningContent = $derived((message?.reasoningContent || '').length > 0 || message?.isThinking === true);
	let shouldShowLoading = $derived(
		(!hasTextContent && !hasReasoningContent) ||
		(hasTextContent && message?.shouldAnimate !== false && !animationInitialized) ||
		(message?.isRegenerating === true && !hasTextContent && !hasReasoningContent)
	);

	// Timeout for stuck loading states (60 seconds - needs to account for slow model cold starts + RAG processing)
	let isStuckLoading = $state(false);

	$effect(() => {
		// Reset stuck state when loading ends
		if (!shouldShowLoading) {
			isStuckLoading = false;
			return;
		}
		// Start timeout when loading begins - 60s to handle slow initial connections and RAG processing
		const timer = setTimeout(() => {
			isStuckLoading = true;
		}, 60000);
		return () => clearTimeout(timer);
	});

	/**
	 * Animate content incrementally - only animate NEW characters added
	 */
	function animateContentIncremental(fullContent: string) {
		// If content hasn't changed, do nothing
		// UNLESS shouldAnimate has changed to false, in which case we must process
		if (fullContent === lastProcessedContent && message?.shouldAnimate !== false) {
			return;
		}

		// Cancel any ongoing animation
		if (animationFrameId !== null) {
			cancelAnimationFrame(animationFrameId);
			animationFrameId = null;
		}

		// If shouldAnimate is false (historical message or stream done), show immediately without animation
		if (message?.shouldAnimate === false) {
			displayedContent = fullContent;
			isAnimating = false;
			lastProcessedContent = fullContent;
			startTime = null;
			return;
		}

		// If no content or not an assistant message, show immediately
		if (!fullContent || message?.sender !== 'assistant') {
			displayedContent = fullContent;
			isAnimating = false;
			lastProcessedContent = fullContent;
			return;
		}

		// Determine if this is an incremental update or a fresh start
		const isIncremental = fullContent.startsWith(displayedContent) && displayedContent.length > 0;

		if (isIncremental) {
			// Incremental: animate only the NEW characters
			// CRITICAL FIX: Only reset start time if we aren't already animating
			// This prevents "stuttering" when updates arrive faster than the animation frame
			if (!isAnimating || startTime === null) {
				startCharIndex = displayedContent.length;
				startTime = performance.now();
				isAnimating = true;
				// If we have content and were waiting for initialization, mark it now
				if (fullContent.length > 0) {
					animationInitialized = true;
				}
			}

			lastProcessedContent = fullContent;

			function animateIncrement(currentTime: number) {
				if (startTime === null) return;

				const elapsed = currentTime - startTime;
				const charsToAdd = Math.floor(elapsed / typingSpeed);
				const targetIndex = startCharIndex + charsToAdd;

				if (targetIndex >= fullContent.length) {
					// Animation complete
					displayedContent = fullContent;
					isAnimating = false;
					animationFrameId = null;
					startTime = null;
					return;
				}

				// Update displayed content incrementally
				displayedContent = fullContent.slice(0, targetIndex + 1);

				// Continue animation
				animationFrameId = requestAnimationFrame(animateIncrement);
			}

			// Start the incremental animation
			animationFrameId = requestAnimationFrame(animateIncrement);
		} else {
			// Not incremental (content changed completely or is new) - animate from scratch
			displayedContent = '';
			startCharIndex = 0;
			startTime = performance.now();
			isAnimating = true;
			// Note: animationInitialized is set inside the first animation frame
			lastProcessedContent = fullContent;

			function animateFresh(currentTime: number) {
				if (startTime === null) return;

				const elapsed = currentTime - startTime;
				const targetCharIndex = Math.floor(elapsed / typingSpeed);

				if (targetCharIndex >= fullContent.length) {
					// Animation complete
					displayedContent = fullContent;
					isAnimating = false;
					animationFrameId = null;
					startTime = null;
					return;
				}

				// Update displayed content
				displayedContent = fullContent.slice(0, targetCharIndex + 1);
				if (!animationInitialized) {
					animationInitialized = true;
				}

				// Continue animation
				animationFrameId = requestAnimationFrame(animateFresh);
			}

			// Start fresh animation
			animationFrameId = requestAnimationFrame(animateFresh);
		}
	}

	/**
	 * Watch for content changes and trigger animation
	 */
	$effect(() => {
		// CRITICAL: Early return if message is undefined to prevent reactive errors
		if (!message) return;

		// Track message.content changes
		const content = message.content;
		// Track shouldAnimate to snap to finish when done
		const _shouldAnimate = message.shouldAnimate;
		// CRITICAL: Track contentVersion to force reactivity on updates (nullish coalescing for historical messages)
		const _version = message.contentVersion ?? 0;

		// Use untrack to prevent infinite loops when updating displayedContent
		untrack(() => {
			animateContentIncremental(content);
		});
	});

	/**
	 * Cleanup animation on component unmount
	 */
	$effect(() => {
		return () => {
			if (animationFrameId !== null) {
				cancelAnimationFrame(animationFrameId);
			}
		};
	});

	/**
	 * Skip animation and show full content immediately
	 */
	function skipAnimation() {
		if (animationFrameId !== null) {
			cancelAnimationFrame(animationFrameId);
			animationFrameId = null;
		}
		displayedContent = message?.content || '';
		isAnimating = false;
	}
</script>

<div class="message-content-wrapper">
	<!-- Skip Animation Button (only visible during animation) -->
	{#if isAnimating && message?.sender === 'assistant'}
		<button class="skip-animation-button" onclick={skipAnimation} title="Skip animation">
			Skip
		</button>
	{/if}

	<div
		class="message-content {className}"
		class:typewriter={shouldShowTypewriter}
		style="--char-count: {charCount}; --cursor-color: {cursorColor}"
	>
		<!-- Show loading spinner when no content or regenerating -->
		{#if shouldShowLoading}
			<div
				class="flex items-center gap-2 py-2 text-muted-foreground"
				out:fade={{ duration: 250 }}
			>
				{#if isStuckLoading}
					<span class="text-sm text-red-500">Failed to load response. Try refreshing.</span>
				{:else}
					<div class="loading-spinner"></div>
					{#key streamingService.currentStatus}
						<span
							class="text-sm"
							in:fade={{ duration: 400 }}
						>
							{streamingService.currentStatus || 'Thinking...'}
						</span>
					{/key}
				{/if}
			</div>
		{:else}
			<div in:fade={{ duration: 400 }}>
				{#each textSegments as segment}
					{#if segment.type === 'markdown'}
						<Markdown md={segment.content} />
					{:else if segment.type === 'widget' && segment.widgetType === 'stats'}
						<StatsWidget rawData={segment.rawData} messageId={message.id} onRepair={onRepairFormat ? () => onRepairFormat(message.id) : undefined} />
					{/if}
				{/each}

				{#if shouldShowTypewriter}
					<span class="typing-indicator"></span>
				{/if}
			</div>
		{/if}
	</div>
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

	/* Add coloration for blockquotes */
	.message-content :global(blockquote) {
		border-left: 4px solid hsl(var(--primary));
		padding-left: 1rem;
		margin-left: 0;
		color: hsl(var(--muted-foreground));
		font-style: italic;
	}

	/* Enhanced quote styling */
	.message-content :global(blockquote p) {
		color: hsl(var(--foreground) / 0.8);
	}

	/* Code block coloration */
	.message-content :global(pre) {
		background-color: hsl(var(--muted));
		border-radius: 0.375rem;
		padding: 1rem;
		overflow-x: auto;
	}

	.message-content :global(code) {
		background-color: hsl(var(--muted));
		border-radius: 0.25rem;
		padding: 0.125rem 0.25rem;
		font-size: 0.875em;
	}

	.message-content :global(pre code) {
		background-color: transparent;
		padding: 0;
	}

	/* Emphasis coloration */
	.message-content :global(em) {
		color: hsl(var(--foreground));
		font-style: italic;
	}

	.message-content :global(strong) {
		color: hsl(var(--foreground));
		font-weight: 600;
	}

	/* Link coloration */
	.message-content :global(a) {
		color: hsl(var(--primary));
		text-decoration: underline;
		text-decoration-color: hsl(var(--primary) / 0.3);
		transition: text-decoration-color 0.2s;
	}

	.message-content :global(a:hover) {
		text-decoration-color: hsl(var(--primary));
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

	/* Pulsing dot indicator for streaming */
	.typing-indicator {
		display: inline-block;
		width: 8px;
		height: 8px;
		margin-left: 4px;
		background-color: hsl(var(--primary));
		border-radius: 50%;
		animation: pulse 1.5s ease-in-out infinite;
		vertical-align: middle;
	}

	@keyframes pulse {
		0%,
		100% {
			opacity: 0.3;
			transform: scale(0.8);
		}
		50% {
			opacity: 1;
			transform: scale(1);
		}
	}

	/* Responsive adjustments */
	@media (max-width: 768px) {
		.typewriter {
			font-size: 0.95rem;
		}
	}

	/* Message content wrapper for positioning skip button */
	.message-content-wrapper {
		position: relative;
	}

	/* Skip animation button */
	.skip-animation-button {
		position: absolute;
		top: 0;
		right: 0;
		padding: 0.25rem 0.5rem;
		font-size: 0.75rem;
		background-color: hsl(var(--primary));
		color: hsl(var(--primary-foreground));
		border: none;
		border-radius: 0.25rem;
		cursor: pointer;
		opacity: 0.7;
		transition: opacity 0.2s;
		z-index: 10;
	}

	.skip-animation-button:hover {
		opacity: 1;
	}
</style>
